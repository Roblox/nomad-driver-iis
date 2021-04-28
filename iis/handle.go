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
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/stats"
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
	waitCh         chan struct{}
	exitResult     *drivers.ExitResult
	totalCpuStats  *stats.CpuStats
	userCpuStats   *stats.CpuStats
	systemCpuStats *stats.CpuStats
	websiteStarted bool
}

func (h *taskHandle) ExitResult() *drivers.ExitResult {
	h.stateLock.Lock()
	defer h.stateLock.Unlock()
	return h.exitResult.Copy()
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

func (h *taskHandle) run() {
	// for {
	// 	if isRunning, err := IsWebsiteRunning(h.taskConfig.AllocID); err != nil {
	// 		h.logger.Error("failed to wait for website; already terminated")
	// 	} else if !isRunning {
	// 		h.procState = drivers.TaskStateExited
	// 	}
	// }

	//h.websiteStarted = true

	// Blocker code to monitor current task running status.
	// On IIS task not running, set driver exit result and return.
	var isRunning bool
	var err error
	for {
		isRunning, err = IsWebsiteRunning(h.taskConfig.AllocID)
		if err != nil || !isRunning {
			// result = &drivers.ExitResult{
			// 	Err: fmt.Errorf("executor: error waiting on process: %v", err),
			// }
			break
		}
		// if !isRunning {
		// 	result = &drivers.ExitResult{
		// 		ExitCode: 0,
		// 	}
		// 	break
		// }
		time.Sleep(time.Second * 5)
	}

	// Set the result
	// IIS doesn't emit exit results on a site stopping. Maybe find a different solution to help provide why IIS has stopped.
	h.stateLock.Lock()
	h.exitResult = &drivers.ExitResult{
		ExitCode: 0,
		Signal:   0,
		Err:      err,
	}
	h.stateLock.Unlock()
	close(h.waitCh)
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
		stats, err := GetWebsiteStats(h.taskConfig.AllocID)
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
func (h *taskHandle) getTaskResourceUsage(stats *WmiProcessStats) *drivers.TaskResourceUsage {
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

	if err := StopWebsite(h.taskConfig.AllocID); err != nil {
		return err
	}

	// Sleep for timeout duration to allow StopWebsite to finish gracefully.
	time.Sleep(timeout)

	return nil
}

func (h *taskHandle) cleanup() error {
	err := DeleteWebsite(h.taskConfig.AllocID)
	if err != nil {
		return fmt.Errorf("Error in destroying website: %v", err)
	}

	return nil
}
