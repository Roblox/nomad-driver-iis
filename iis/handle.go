package iis

import (
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
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
	pidCollector   *pidCollector
	systemCpuStats *stats.CpuStats
}

func (h *taskHandle) TaskStatus() *drivers.TaskStatus {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()

	isRunning, err := isWebsiteRunning(h.TaskConfig.AllocID)
	if err != nil {
		h.logger.Error("Error in getting task status: %v", err)
		h.procState = drivers.TaskStateExited
	}

	if !isRunning {
		h.procState = drivers.TaskStateExited
	}

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
	if !filepath.IsAbs(driverConfig.Path) {
		driverConfig.Path = filepath.Join(h.taskConfig.TaskDir().Dir, driverConfig.Path)
	}

	// Gather Network Ports: http or https only
	networks := h.taskConfig.Resources.NomadResources.Networks
	if len(networks) == 0 {
		errMsg := "Error in launching task: Trying to map ports but no network interface is available"
		h.handleError(errMsg, errors.New(errMsg))
		return
	}

	var iisBindings []IISBinding
	for _, binding := range driverConfig.Bindings {
		if binding.Port == 0 && binding.ResourcePort == "" {
			errMsg := "Error in launching task: both binding.Port and binding.ResourcePort cannot be unset."
			h.handleError(errMsg, errors.New(errMsg))
			return
		}

		if binding.Port < 0 {
			errMsg := "Error in launching task: binding.Port cannot be negative."
			h.handleError(errMsg, errors.New(errMsg))
			return
		}

		if binding.Port > 0 {
			iisBindings = append(iisBindings, binding)
			continue
		}

		for _, network := range networks {
			for _, dynamicPort := range network.DynamicPorts {
				if binding.ResourcePort == dynamicPort.Label {
					binding.Port = dynamicPort.Value
					iisBindings = append(iisBindings, binding)
				}
			}
			for _, staticPort := range network.ReservedPorts {
				if binding.ResourcePort == staticPort.Label {
					binding.Port = staticPort.Value
					iisBindings = append(iisBindings, binding)
				}
			}
		}
	}

	driverConfig.Bindings = iisBindings

	if err := createWebsite(h.taskConfig.AllocID, driverConfig); err != nil {
		errMsg := fmt.Sprintf("Error in creating website: %v", err)
		h.handleError(errMsg, err)
		return
	}

	if err := startWebsite(h.taskConfig.AllocID); err != nil {
		errMsg := fmt.Sprintf("Error in starting website: %v", err)
		h.handleError(errMsg, err)
		return
	}
}

// handleError will log the error message (errMsg) and update the task handle with exit results.
func (h *taskHandle) handleError(errMsg string, err error) {
	h.logger.Error(errMsg)
	h.exitResult.Err = err
	h.procState = drivers.TaskStateUnknown
	h.completedAt = time.Now()
}
