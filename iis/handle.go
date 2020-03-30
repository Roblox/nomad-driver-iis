package iis

import (
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
		h.logger.Error("Error in launching the task: Trying to map ports but no network interface is available")
		return
	}

	var iisBindings []IISBinding
	for _, binding := range driverConfig.Bindings {
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
		h.logger.Error("Error in creating website: %v", err)
		return
	}

	if err := startWebsite(h.taskConfig.AllocID); err != nil {
		h.logger.Error("Error in starting website: %v", err)
		return
	}
}
