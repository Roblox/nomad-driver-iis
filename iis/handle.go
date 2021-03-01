/*
Copyright 2020 Roblox Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0


Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package iis

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/stats"
	shelpers "github.com/hashicorp/nomad/helper/stats"
	"github.com/hashicorp/nomad/plugins/drivers"
)

// taskHandle should store all relevant runtime information
// such as process ID if this is a local task or other meta
// data if this driver deals with external APIs
type taskHandle struct {
	// stateLock syncs access to all fields below
	stateLock sync.RWMutex

	logger         hclog.Logger
	taskConfig     *drivers.TaskConfig
	procState      drivers.TaskState
	startedAt      time.Time
	completedAt    time.Time
	exitResult     *drivers.ExitResult
	totalCpuStats  *stats.CpuStats
	userCpuStats   *stats.CpuStats
	systemCpuStats *stats.CpuStats
	websiteStarted bool
}

func (h *taskHandle) TaskStatus() *drivers.TaskStatus {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()

	return &drivers.TaskStatus{
		ID:          h.taskConfig.ID,
		Name:        h.taskConfig.Name,
		State:       h.procState,
		StartedAt:   h.startedAt,
		CompletedAt: h.completedAt,
		ExitResult:  h.exitResult,
	}
}

func (h *taskHandle) IsRunning() bool {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()
	return h.procState == drivers.TaskStateRunning
}

func (h *taskHandle) run(driverConfig *TaskConfig) {
	// Every executor runs this init at creation for stats
	if err := shelpers.Init(); err != nil {
		h.logger.Error("unable to initialize stats", "error", err)
	}

	websiteConfig := WebsiteConfig{
		Name: h.taskConfig.AllocID,
		Env:  map[string]string{},
		AppPoolIdentity: iisAppPoolIdentity{
			Identity: driverConfig.AppPoolIdentity,
		},
		AppPoolConfigPath: driverConfig.AppPoolConfigPath,
		SiteConfigPath:    driverConfig.SiteConfigPath,
	}

	// Setup environment variables.
	// NOMAD_APPPOOL_* are keywords for applying user/pass info for a given Application Pool in a secure manner
	for key, val := range h.taskConfig.Env {
		switch key {
		case "NOMAD_APPPOOL_USERNAME":
			websiteConfig.AppPoolIdentity.Identity = "SpecificUser"
			websiteConfig.AppPoolIdentity.Username = val
		case "NOMAD_APPPOOL_PASSWORD":
			websiteConfig.AppPoolIdentity.Password = val
		default:
			websiteConfig.Env[key] = val
		}
	}

	if !filepath.IsAbs(driverConfig.Path) {
		websiteConfig.Path = filepath.Join(h.taskConfig.TaskDir().Dir, driverConfig.Path)
	} else {
		websiteConfig.Path = driverConfig.Path
	}

	var iisBindings []iisBinding
	// If any bindings were specified, we move forward with port label cross lookups
	if len(driverConfig.Bindings) > 0 {
		if h.taskConfig.Resources.Ports != nil {
			// parse group/shared resource ports. This is the preferred route for establishing network ports
			// here is the relevant PR for the docker driver that drove this change: https://github.com/hashicorp/nomad/pull/8623

			for _, binding := range driverConfig.Bindings {
				if port, ok := h.taskConfig.Resources.Ports.Get(binding.PortLabel); ok {
					binding.Port = port.Value
					iisBindings = append(iisBindings, binding)
				} else {
					errMsg := fmt.Sprintf("Port %s not found, check network stanza", binding.PortLabel)
					h.handleError(errMsg, errors.New(errMsg))
					return
				}
			}
		} else if len(h.taskConfig.Resources.NomadResources.Networks) > 0 {
			// parses a task's network stanza for dynamic/static ports
			// this is deprecated as of Nomad v1.0+, in time this should be removed
			// just like the docker driver, you can only work with one network stanza format over another

			for _, binding := range driverConfig.Bindings {
				foundPort := false
				for _, network := range h.taskConfig.Resources.NomadResources.Networks {

					for _, port := range network.ReservedPorts {
						binding.Port = port.Value
						iisBindings = append(iisBindings, binding)
						foundPort = true
					}

					for _, port := range network.DynamicPorts {
						binding.Port = port.Value
						iisBindings = append(iisBindings, binding)
						foundPort = true
					}
				}
				if !foundPort {
					errMsg := fmt.Sprintf("Port %s not found, check network stanza", binding.PortLabel)
					h.handleError(errMsg, errors.New(errMsg))
					return
				}
			}
		}
	}

	websiteConfig.Bindings = iisBindings

	if err := createWebsite(&websiteConfig); err != nil {
		errMsg := fmt.Sprintf("Error in creating website: %v", err)
		h.handleError(errMsg, err)
		return
	}

	if err := startWebsite(websiteConfig.Name); err != nil {
		errMsg := fmt.Sprintf("Error in starting website: %v", err)
		h.handleError(errMsg, err)
		return
	}

	h.websiteStarted = true
}

// handleError will log the error message (errMsg) and update the task handle with exit results.
func (h *taskHandle) handleError(errMsg string, err error) {
	h.logger.Error(errMsg)
	h.exitResult.Err = err
	h.procState = drivers.TaskStateUnknown
	h.completedAt = time.Now()
}

func (h *taskHandle) Stats(ctx context.Context, interval time.Duration) (<-chan *drivers.TaskResourceUsage, error) {
	ch := make(chan *drivers.TaskResourceUsage)
	go h.handleStats(ch, ctx, interval)

	return ch, nil
}

func (h *taskHandle) handleStats(ch chan *drivers.TaskResourceUsage, ctx context.Context, interval time.Duration) {
	defer close(ch)
	timer := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return

		case <-timer.C:
			timer.Reset(interval)
		}

		// Get IIS Worker Process stats if we can.
		stats, err := getWebsiteStats(h.taskConfig.AllocID)
		if err != nil {
			h.logger.Error("Failed to get iis worker process stats:", "error", err)
			return
		}

		select {
		case <-ctx.Done():
			return
		case ch <- h.getTaskResourceUsage(stats):
		}
	}
}

// Convert IIS WMI Tasks Info to driver TaskResourceUsage expected input
func (h *taskHandle) getTaskResourceUsage(stats *wmiProcessStats) *drivers.TaskResourceUsage {
	totalPercent := h.totalCpuStats.Percent(float64(stats.KernelModeTime + stats.UserModeTime))
	cs := &drivers.CpuStats{
		SystemMode: h.systemCpuStats.Percent(float64(stats.KernelModeTime)),
		UserMode:   h.userCpuStats.Percent(float64(stats.UserModeTime)),
		Percent:    totalPercent,
		Measured:   []string{"Percent", "System Mode", "User Mode"},
		TotalTicks: h.totalCpuStats.TicksConsumed(totalPercent),
	}

	ms := &drivers.MemoryStats{
		RSS:      stats.WorkingSetPrivate,
		Measured: []string{"RSS"},
	}

	ts := time.Now().UTC().UnixNano()
	return &drivers.TaskResourceUsage{
		ResourceUsage: &drivers.ResourceUsage{
			CpuStats:    cs,
			MemoryStats: ms,
		},
		Timestamp: ts,
	}
}

func (h *taskHandle) shutdown(timeout time.Duration) error {
	h.stateLock.Lock()
	defer h.stateLock.Unlock()

	if err := stopWebsite(h.taskConfig.AllocID); err != nil {
		return err
	}

	// Sleep for timeout duration to allow stopWebsite to finish gracefully.
	time.Sleep(timeout)

	return nil
}

func (h *taskHandle) cleanup() error {
	err := deleteWebsite(h.taskConfig.AllocID)
	if err != nil {
		return fmt.Errorf("Error in destroying website: %v", err)
	}

	return nil
}
