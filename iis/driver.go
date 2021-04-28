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
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/stats"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	shelpers "github.com/hashicorp/nomad/helper/stats"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
	"github.com/hashicorp/nomad/plugins/shared/structs"
)

const (
	// pluginName is the name of the plugin
	// this is used for logging and (along with the version) for uniquely
	// identifying plugin binaries fingerprinted by the client
	pluginName = "win_iis"

	// pluginVersion allows the client to identify and use newer versions of
	// an installed plugin
	pluginVersion = "0.2.2"

	// fingerprintPeriod is the interval at which the plugin will send
	// fingerprint responses
	fingerprintPeriod = 30 * time.Second

	// taskHandleVersion is the version of task handle which this plugin sets
	// and understands how to decode
	// this is used to allow modification and migration of the task schema
	// used by the plugin
	taskHandleVersion = 1
)

var (
	// pluginInfo describes the plugin
	pluginInfo = &base.PluginInfoResponse{
		Type:              base.PluginTypeDriver,
		PluginApiVersions: []string{drivers.ApiVersion010},
		PluginVersion:     pluginVersion,
		Name:              pluginName,
	}

	// configSpec is the specification of the plugin's configuration
	// this is used to validate the configuration specified for the plugin
	// on the client.
	// this is not global, but can be specified on a per-client basis.
	configSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"enabled": hclspec.NewDefault(
			hclspec.NewAttr("enabled", "bool", false),
			hclspec.NewLiteral("true"),
		),
		"stats_interval": hclspec.NewAttr("stats_interval", "string", false),
	})

	// taskConfigSpec is the specification of the plugin's configuration for
	// a task
	// this is used to validated the configuration specified for the plugin
	// when a job is submitted.
	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"path":                hclspec.NewAttr("path", "string", true),
		"site_config_path":    hclspec.NewAttr("site_config_path", "string", false),
		"apppool_config_path": hclspec.NewAttr("apppool_config_path", "string", false),
		"apppool_identity":    hclspec.NewAttr("apppool_identity", "string", false),
		"bindings": hclspec.NewBlockList("bindings", hclspec.NewObject(map[string]*hclspec.Spec{
			"hostname":  hclspec.NewAttr("hostname", "string", false),
			"ipaddress": hclspec.NewAttr("ipaddress", "string", false),
			"port":      hclspec.NewAttr("port", "string", true),
			"type":      hclspec.NewAttr("type", "string", true),
			"cert_name": hclspec.NewAttr("cert_name", "string", false),
			"cert_hash": hclspec.NewAttr("cert_hash", "string", false),
		})),
	})

	// capabilities indicates what optional features this driver supports
	// this should be set according to the target run time.
	capabilities = &drivers.Capabilities{
		// The plugin's capabilities signal Nomad which extra functionalities
		// are supported. For a list of available options check the docs page:
		// https://godoc.org/github.com/hashicorp/nomad/plugins/drivers#Capabilities
		SendSignals: false,
		Exec:        false,
		FSIsolation: drivers.FSIsolationNone,
	}
)

// Config contains configuration information for the plugin
type Config struct {
	// Enabled is set to true to enable the win_iis driver
	Enabled       bool   `codec:"enabled"`
	StatsInterval string `codec:"stats_interval"`
}

// TaskConfig contains configuration information for a task that runs with
// this plugin
type TaskConfig struct {
	Path              string       `codec:"path"`
	AppPoolConfigPath string       `codec:"apppool_config_path"`
	SiteConfigPath    string       `codec:"site_config_path"`
	AppPoolIdentity   string       `codec:"apppool_identity"`
	Bindings          []iisBinding `codec:"bindings"`
}

// TaskState is the runtime state which is encoded in the handle returned to
// Nomad client.
// This information is needed to rebuild the task state and handler during
// recovery.
type TaskState struct {
	StartedAt time.Time
}

// Driver is a driver for running windows IIS tasks.
type Driver struct {
	// eventer is used to handle multiplexing of TaskEvents calls such that an
	// event can be broadcast to all callers
	eventer *eventer.Eventer

	// config is the plugin configuration set by the SetConfig RPC
	config *Config

	// nomadConfig is the client config from Nomad
	nomadConfig *base.ClientDriverConfig

	// tasks is the in memory datastore mapping taskIDs to driver handles
	tasks *taskStore

	// ctx is the context for the driver. It is passed to other subsystems to
	// coordinate shutdown
	ctx context.Context

	// signalShutdown is called when the driver is shutting down and cancels
	// the ctx passed to any subsystems
	signalShutdown context.CancelFunc

	// logger will log to the Nomad agent
	logger log.Logger
}

// NewIISDriver returns a new driver plugin implementation.
func NewIISDriver(logger hclog.Logger) drivers.DriverPlugin {
	ctx, cancel := context.WithCancel(context.Background())
	logger = logger.Named(pluginName)

	return &Driver{
		eventer:        eventer.NewEventer(ctx, logger),
		config:         &Config{},
		tasks:          newTaskStore(),
		ctx:            ctx,
		signalShutdown: cancel,
		logger:         logger,
	}
}

// PluginInfo returns information describing the plugin.
func (d *Driver) PluginInfo() (*base.PluginInfoResponse, error) {
	return pluginInfo, nil
}

// ConfigSchema returns the plugin configuration schema.
func (d *Driver) ConfigSchema() (*hclspec.Spec, error) {
	return configSpec, nil
}

// SetConfig is called by the client to pass the configuration for the plugin.
func (d *Driver) SetConfig(cfg *base.Config) error {
	var config Config
	if len(cfg.PluginConfig) != 0 {
		if err := base.MsgPackDecode(cfg.PluginConfig, &config); err != nil {
			return err
		}
	}

	// Save the configuration to the plugin
	d.config = &config

	// Save the Nomad agent configuration
	if cfg.AgentConfig != nil {
		d.nomadConfig = cfg.AgentConfig.Driver
	}

	return nil
}

// TaskConfigSchema returns the HCL schema for the configuration of a task.
func (d *Driver) TaskConfigSchema() (*hclspec.Spec, error) {
	return taskConfigSpec, nil
}

// Capabilities returns the features supported by the driver.
func (d *Driver) Capabilities() (*drivers.Capabilities, error) {
	return capabilities, nil
}

// Fingerprint returns a channel that will be used to send health information
// and other driver specific node attributes.
func (d *Driver) Fingerprint(ctx context.Context) (<-chan *drivers.Fingerprint, error) {
	ch := make(chan *drivers.Fingerprint)
	go d.handleFingerprint(ctx, ch)
	return ch, nil
}

// handleFingerprint manages the channel and the flow of fingerprint data.
func (d *Driver) handleFingerprint(ctx context.Context, ch chan<- *drivers.Fingerprint) {
	defer close(ch)

	// Nomad expects the initial fingerprint to be sent immediately
	ticker := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			// after the initial fingerprint we can set the proper fingerprint
			// period
			ticker.Reset(fingerprintPeriod)
			ch <- d.buildFingerprint()
		}
	}
}

// buildFingerprint returns the driver's fingerprint data
// Gets IIS version and checks running state in SC
func (d *Driver) buildFingerprint() *drivers.Fingerprint {
	fp := &drivers.Fingerprint{
		Attributes: map[string]*structs.Attribute{
			"driver.win_iis.version": structs.NewStringAttribute(pluginVersion),
		},
		Health:            drivers.HealthStateHealthy,
		HealthDescription: drivers.DriverHealthy,
	}

	// Check if IIS is running in SC
	if isRunning, err := IsIISRunning(); err != nil {
		d.logger.Error("Error in building fingerprint, when trying to get IIS running status: %v", err)
		fp.Health = drivers.HealthStateUndetected
		fp.HealthDescription = "Undetected"
		return fp
	} else if !isRunning {
		fp.Health = drivers.HealthStateUnhealthy
		fp.HealthDescription = "Unhealthy"
		return fp
	}

	// Get IIS version
	version, err := getVersionStr()
	if err != nil {
		d.logger.Warn("Error in building fingerprint: failed to find IIS version: %v", err)
		return fp
	}

	fp.Attributes["driver.win_iis.iis_version"] = structs.NewStringAttribute(version)

	return fp
}

// StartTask returns a task handle and a driver network if necessary.
func (d *Driver) StartTask(cfg *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	d.logger.Info("win_iis task driver: Start Task.")
	if _, ok := d.tasks.Get(cfg.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", cfg.ID)
	}

	var driverConfig TaskConfig
	if err := cfg.DecodeDriverConfig(&driverConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to decode driver config: %v", err)
	}

	d.logger.Info("starting iis task", "driver_cfg", hclog.Fmt("%+v", driverConfig))
	handle := drivers.NewTaskHandle(taskHandleVersion)
	handle.Config = cfg

	h := &taskHandle{
		taskConfig:     cfg,
		procState:      drivers.TaskStateRunning,
		startedAt:      time.Now().Round(time.Millisecond),
		logger:         d.logger,
		totalCpuStats:  stats.NewCpuStats(),
		userCpuStats:   stats.NewCpuStats(),
		systemCpuStats: stats.NewCpuStats(),
		websiteStarted: false,
		waitCh:         make(chan struct{}),
	}

	driverState := TaskState{
		StartedAt: h.startedAt,
	}

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
					// errMsg := fmt.Sprintf("Port %s not found, check network stanza", binding.PortLabel)
					// h.handleError(errMsg, errors.New(errMsg))
					// return
					return nil, nil, fmt.Errorf("Port %s not found, check network stanza", binding.PortLabel)
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
					//errMsg := fmt.Sprintf("Port %s not found, check network stanza", binding.PortLabel)
					//h.handleError(errMsg, errors.New(errMsg))
					return nil, nil, fmt.Errorf("Port %s not found, check network stanza", binding.PortLabel)
				}
			}
		}
	}

	// Validate config bindings for https
	// First we gather currently installed certs
	// This may be best lived in iis.go with the bindings code
	//   For now, it is here as I hack through tests and migrating code to other PRs
	certs, err := getIISCerts()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to gather installed certs: %v", err)
	}
	for i := 0; i < len(iisBindings); i++ {
		if iisBindings[i].CertHash != "" {
			// check if cert thumbprint(hash) exists
			certExists := false
			for _, cert := range certs {
				if strings.EqualFold(cert.Thumbprint, iisBindings[i].CertHash) {
					certExists = true
					break
				}
			}
			if !certExists {
				return nil, nil, fmt.Errorf("Failed to find cert_hash with thumbprint of '%s'", iisBindings[i].CertHash)
			}
		} else if iisBindings[i].CertName != "" {
			certExists := false
			var maxExpirationDate time.Time
			for _, cert := range certs {
				// Find certs with the same FriendlyName or CN
				// If there exists a cert with the names we are looking for, then ensure we get the one with the further expiration date
				if cert.FriendlyName == iisBindings[i].CertName || cert.CN == iisBindings[i].CertName {
					if maxExpirationDate.Before(cert.NotAfter) {
						certExists = true
						maxExpirationDate = cert.NotAfter
						iisBindings[i].CertHash = cert.Thumbprint
					}
				}
			}
			if !certExists {
				return nil, nil, fmt.Errorf("Failed to find cert_hash with name of '%s'", iisBindings[i].CertName)
			}
		}
	}

	websiteConfig.Bindings = iisBindings

	if err := CreateWebsite(&websiteConfig); err != nil {
		d.logger.Error("Error in creating website: ", err)
		return nil, nil, err
	}

	if err := StartWebsite(websiteConfig.Name); err != nil {
		d.logger.Error("Error in starting website: ", err)
		return nil, nil, err
	}

	if err := handle.SetDriverState(&driverState); err != nil {
		return nil, nil, fmt.Errorf("failed to set driver state: %v", err)
	}

	d.tasks.Set(cfg.ID, h)
	go h.run()
	return handle, nil, nil
}

// RecoverTask recreates the in-memory state of a task from a TaskHandle.
func (d *Driver) RecoverTask(handle *drivers.TaskHandle) error {
	d.logger.Info("win_iis task driver: Recover Task")
	if handle == nil {
		return fmt.Errorf("error: handle cannot be nil")
	}

	if _, ok := d.tasks.Get(handle.Config.ID); ok {
		return nil
	}

	var taskState TaskState
	if err := handle.GetDriverState(&taskState); err != nil {
		return fmt.Errorf("failed to decode task state from handle: %v", err)
	}

	// var driverConfig TaskConfig
	// if err := handle.Config.DecodeDriverConfig(&driverConfig); err != nil {
	// 	return fmt.Errorf("failed to decode driver config: %v", err)
	// }

	h := &taskHandle{
		taskConfig:     handle.Config,
		procState:      drivers.TaskStateRunning,
		startedAt:      taskState.StartedAt,
		exitResult:     &drivers.ExitResult{},
		logger:         d.logger,
		totalCpuStats:  stats.NewCpuStats(),
		userCpuStats:   stats.NewCpuStats(),
		systemCpuStats: stats.NewCpuStats(),
		websiteStarted: false,
		waitCh:         make(chan struct{}),
	}

	d.tasks.Set(handle.Config.ID, h)

	go h.run()
	d.logger.Info("win_iis task driver: Task recovered successfully.")
	return nil
}

// WaitTask returns a channel used to notify Nomad when a task exits.
func (d *Driver) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	ch := make(chan *drivers.ExitResult)
	go d.handleWait(ctx, handle, ch)
	return ch, nil
}

func (d *Driver) handleWait(ctx context.Context, handle *taskHandle, ch chan *drivers.ExitResult) {
	defer close(ch)
	select {
	case <-handle.waitCh:
		ch <- handle.ExitResult()
	case <-ctx.Done():
		ch <- &drivers.ExitResult{
			Err: ctx.Err(),
		}
	}
}

// StopTask stops a running task with the given signal and within the timeout window.
func (d *Driver) StopTask(taskID string, timeout time.Duration, signal string) error {
	d.logger.Info("win_iis task driver: Stop Task")
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	if err := handle.shutdown(timeout); err != nil {
		return fmt.Errorf("Error stopping iis task: %v", err)
	}

	return nil
}

// DestroyTask cleans up and removes a task that has terminated.
func (d *Driver) DestroyTask(taskID string, force bool) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	// Destroying a task includes removing any resources used by task and any
	// local references in the plugin. If force is set to true the task should
	// be destroyed even if it's currently running.
	if handle.IsRunning() && !force {
		return fmt.Errorf("cannot destroy running task")
	}

	if err := handle.cleanup(); err != nil {
		return err
	}

	d.tasks.Delete(taskID)
	return nil
}

// InspectTask returns detailed status information for the referenced taskID.
func (d *Driver) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	return handle.TaskStatus(), nil
}

// TaskStats returns a channel which the driver should send stats to at the given interval.
func (d *Driver) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *drivers.TaskResourceUsage, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	if d.config.StatsInterval != "" {
		statsInterval, err := time.ParseDuration(d.config.StatsInterval)
		if err != nil {
			d.logger.Warn("Error parsing driver stats interval, fallback on default interval")
		} else {
			msg := fmt.Sprintf("Overriding client stats interval: %v with driver stats interval: %v", interval, d.config.StatsInterval)
			d.logger.Debug(msg)
			interval = statsInterval
		}
	}

	return handle.Stats(ctx, interval)
}

// TaskEvents returns a channel that the plugin can use to emit task related events.
func (d *Driver) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	return d.eventer.TaskEvents(ctx)
}

// SignalTask forwards a signal to a task.
// This is an optional capability.
// IIS doesn't natively allow users to send signals, so this driver will abide by that.
func (d *Driver) SignalTask(taskID string, signal string) error {
	return fmt.Errorf("This driver does not support signals")
}

// ExecTask returns the result of executing the given command inside a task.
// This is an optional capability.
func (d *Driver) ExecTask(taskID string, cmd []string, timeout time.Duration) (*drivers.ExecTaskResult, error) {
	return nil, fmt.Errorf("This driver does not support exec")
}
