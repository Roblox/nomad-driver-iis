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
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	wmi "github.com/StackExchange/wmi"
)

var mux sync.Mutex

// Application Pool schema given from appcmd.exe
type appCmdAppPool struct {
	Name           string     `xml:"APPPOOL.NAME,attr"`
	PipelineMode   string     `xml:"PipelineMode,attr"`
	RuntimeVersion string     `xml:"RuntimeVersion,attr"`
	State          string     `xml:"state,attr"`
	Add            appPoolAdd `xml:"add"`
}

// An Application Pool's inner schema to describe the ApplicationPool given from appcmd.exe
type appPoolAdd struct {
	Name         string              `xml:"name,attr"`
	QueueLength  int                 `xml:"queueLength,attr"`
	AutoStart    bool                `xml:"autoStart,attr"`
	ProcessModel appPoolProcessModel `xml:"processModel"`
}

// An Application Pool's ProcessModel schema given from appcmd.exe
type appPoolProcessModel struct {
	IdentityType string `xml:"identityType,attr"`
	Password     string `xml:"password,attr"`
	Username     string `xml:"userName,attr"`
}

// AppCmd message schema used for errors and messages
type appCmdMessage struct {
	Message string `xml:"message,attr"`
}

// AppCmd schema for all results
type appCmdResult struct {
	AppPools        []appCmdAppPool `xml:"APPPOOL"`
	Errors          []appCmdMessage `xml:"ERROR"`
	Sites           []appCmdSite    `xml:"SITE"`
	Statuses        []appCmdMessage `xml:"STATUS"`
	WorkerProcesses []appCmdWP      `xml:"WP"`
	XMLName         xml.Name        `xml:"appcmd"`
}

// Site schema given from appcmd.exe
type appCmdSite struct {
	Bindings string `xml:"bindings,attr"`
	ID       int    `xml:"SISTE.ID,attr"`
	Name     string `xml:"SITE.NAME,attr"`
	State    string `xml:"state,attr"`
	Site     site   `xml:"site"`
}

// Nested Site schema given from appcmd.exe
type site struct {
	Name        string          `xml:"name,attr"`
	ID          string          `xml:"id,attr"`
	Application siteApplication `xml:"application"`
}

// A Site's Application schema given from appcmd.exe
type siteApplication struct {
	Path            string     `xml:"path,attr"`
	ApplicationPool string     `xml:"applicationPool,attr"`
	VDirs           []siteVDir `xml:"virtualDirectory"`
}

// A Site's Virtual Directory schema given from appcmd.exe
type siteVDir struct {
	Path         string `xml:"path,attr"`
	PhysicalPath string `xml:"physicalPath,attr"`
}

// Worker Process schema given from appcmd.exe
type appCmdWP struct {
	AppPoolName string `xml:"APPPOOL.NAME,attr"`
	Name        string `xml:"WP.NAME,attr"`
}

// IIS Identity used for an Application Pool
type iisAppPoolIdentity struct {
	Identity string `codec:"identity"`
	Password string `codec:"password"`
	Username string `codec:"username"`
}

// IIS ResourceLimit used for Application pool worker process
type iisResourceLimit struct {
	CPULimit    int `codec:"cpu_limit"`
	MemoryLimit int `codec:"memory_limit"`
}

// IIS Binding struct to match
type iisBinding struct {
	CertHash     string `codec:"cert_hash"`
	HostName     string `codec:"hostname"`
	IPAddress    string `codec:"ipaddress"`
	Port         int    `codec:"port"`
	ResourcePort string `codec:"resource_port"`
	Type         string `codec:"type"`
}

// Stat fields that are unmarshalled from WMI
type wmiProcessStats struct {
	KernelModeTime    uint64
	UserModeTime      uint64
	WorkingSetPrivate uint64
}

// Gets the exe version of InetMgr.exe
func getVersion() (string, error) {
	cmd := exec.Command("cmd", "/C", `wmic datafile where name='C:\\Windows\\System32\\inetsrv\\InetMgr.exe' get version`)
	if out, err := cmd.Output(); err != nil {
		return "", fmt.Errorf("Failed to determine version: %v", err)
	} else {
		if output := strings.Fields(string(out)); len(output) != 2 {
			return "", fmt.Errorf("Did not receive proper version formatting")
		} else {
			return output[1], nil
		}
	}
}

// Returns if the IIS service is running in Windows Service Controller (SC)
func isIISRunning() (bool, error) {
	cmd := exec.Command(`C:\Windows\System32\sc.exe`, "query", "w3svc")
	if out, err := cmd.CombinedOutput(); err != nil {
		return false, err
	} else {
		return regexp.MatchString(`STATE.*:.*4.*RUNNING`, string(out))
	}
}

// Removes all Application Pools and Sites from IIS
func purgeIIS() error {
	if sites, err := getSites(); err != nil {
		return err
	} else {
		for _, site := range sites {
			if err = deleteSite(site.Name); err != nil {
				return err
			}
		}
	}
	if appPools, err := getAppPools(); err != nil {
		return err
	} else {
		for _, appPool := range appPools {
			if err = deleteAppPool(appPool.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// Starts the IIS service in Windows SC
func startIIS() error {
	if isRunning, err := isIISRunning(); err != nil || isRunning {
		return err
	}

	cmd := exec.Command(`C:\Windows\System32\sc.exe`, "start", "w3svc")
	if _, err := cmd.Output(); err != nil {
		return err
	}
	return nil
}

// Stops the IIS service in Windows SC
func stopIIS() error {
	if isRunning, err := isIISRunning(); err != nil || !isRunning {
		return err
	}

	cmd := exec.Command(`C:\Windows\System32\sc.exe`, "stop", "w3svc")
	if _, err := cmd.Output(); err != nil {
		return err
	}
	return nil
}

// Executes appcmd.exe with the given arguments and returns a structured result or error
func executeAppCmd(arg ...string) (appCmdResult, error) {
	return executeAppCmdWithInput("", arg...)
}

// Executes appcmd.exe with the given arguments along with an xml path file for input and returns a structured result or error
func executeAppCmdWithInput(importXmlPath string, arg ...string) (appCmdResult, error) {
	var result appCmdResult
	var cmd *exec.Cmd

	arg = append(arg, "/xml")
	if importXmlPath != "" {
		arg = append([]string{"/C", `C:\Windows\System32\inetsrv\APPCMD.exe`}, append(arg, fmt.Sprintf("/in<%s", importXmlPath))...)
		cmd = exec.Command("cmd", arg...)
	} else {
		cmd = exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, arg...)
	}

	if out, err := cmd.Output(); err != nil {
		// Attempt to parse output for verbose error messages in xml, otherwise return error code
		// If an appcmd xml is parsed successfully, then accept that as source of error truth
		if xmlErr := xml.Unmarshal(out, &result); xmlErr == nil {
			if len(result.Errors) != 0 {
				return result, fmt.Errorf(result.Errors[0].Message)
			}

			return result, nil
		}
		return result, err
	} else {
		xml.Unmarshal(out, &result)
		return result, nil
	}
}

// Applies the Application Pool identity user settings
func applyAppPoolIdentity(appPoolName string, appPoolIdentity iisAppPoolIdentity) error {
	properties := []string{"set", "config", "/section:applicationPools"}

	if appPoolIdentity.Identity != "" {
		properties = append(properties, fmt.Sprintf("/[name='%s'].processModel.identityType:%s", appPoolName, appPoolIdentity.Identity))
	}

	if appPoolIdentity.Identity == "SpecificUser" && appPoolIdentity.Username != "" && appPoolIdentity.Password != "" {
		properties = append(properties, fmt.Sprintf("/[name='%s'].processModel.userName:%s", appPoolName, appPoolIdentity.Username))
		properties = append(properties, fmt.Sprintf("/[name='%s'].processModel.password:%s", appPoolName, appPoolIdentity.Password))
	}

	if _, err := executeAppCmd(properties...); err != nil {
		return fmt.Errorf("Failed to set Application Pool identity: %v", err)
	}

	return nil
}

// Applies the Application Pool resource limit
func applyAppPoolResourceLimit(appPoolName string, appPoolResource iisResourceLimit) error {
	properties := []string{"set", "config", "-section:system.applicationHost/applicationPools"}

	if appPoolResource.CPULimit != 0 {

		cpuLimitSize := appPoolResource.CPULimit * 1000

		properties = append(properties, fmt.Sprintf("/[name='%s'].cpu.limit:%s", appPoolName, strconv.Itoa(cpuLimitSize)))
		properties = append(properties, fmt.Sprintf("/commit:apphost"))

		if _, err := executeAppCmd(properties...); err != nil {
			return fmt.Errorf("Failed to set Application Pool Resources: %v", err)
		}
	}
	properties = []string{"set", "config", "-section:system.applicationHost/applicationPools"}

	properties = append(properties, fmt.Sprintf("/[name='%s'].cpu.action:%s", appPoolName, "KillW3wp"))
	properties = append(properties, fmt.Sprintf("/commit:apphost"))
	if _, err := executeAppCmd(properties...); err != nil {
		return fmt.Errorf("Failed to set Application Pool Resources: %v", err)
	}

	properties = []string{"set", "config", "-section:system.applicationHost/applicationPools"}

	if appPoolResource.MemoryLimit != 0 {
		memoryLimitSize := appPoolResource.MemoryLimit * 1000
		properties = append(properties, fmt.Sprintf("/[name='%s'].recycling.periodicRestart.privateMemory:%s", appPoolName, strconv.Itoa(memoryLimitSize)))
		properties = append(properties, fmt.Sprintf("/commit:apphost"))
		if _, err := executeAppCmd(properties...); err != nil {
			return fmt.Errorf("Failed to set Application Pool Resources: %v", err)
		}
	}
	return nil
}

// Creates an Application Pool with the given name and applies an IIS exported Application Pool xml if a path is provided
func createAppPool(appPoolName string, configPath string) error {
	if exists, err := doesAppPoolExist(appPoolName); err != nil || exists {
		return err
	}

	properties := []string{"add", "apppool", fmt.Sprintf("/name:%s", appPoolName)}
	if _, err := executeAppCmdWithInput(configPath, properties...); err != nil {
		return fmt.Errorf("Failed to create Application Pool: %v", err)
	}

	return nil
}

// Deletes an Application Pool with the given name
func deleteAppPool(appPoolName string) error {
	if exists, err := doesAppPoolExist(appPoolName); err != nil || !exists {
		return err
	}

	if _, err := executeAppCmd("delete", "apppool", appPoolName); err != nil {
		return fmt.Errorf("Failed to delete Application Pool: %v", err)
	}

	return nil
}

// Returns if an Application Pool with the given name exists in IIS
func doesAppPoolExist(appPoolName string) (bool, error) {
	if appPool, err := getAppPool(appPoolName, false); err != nil || appPool == nil {
		return false, err
	}
	return true, nil
}

// Returns an Application Pool with the given name
func getAppPool(appPoolName string, allConfigs bool) (*appCmdAppPool, error) {
	args := []string{"list", "apppool", appPoolName}
	if allConfigs {
		args = append(args, "/config:*")
	}

	if result, err := executeAppCmd(args...); err != nil {
		return nil, fmt.Errorf("Failed to get Application Pool: %v", err)
	} else if len(result.AppPools) == 0 {
		return nil, nil
	} else {
		return &result.AppPools[0], nil
	}
}

// Returns all Application Pools that exist in IIS
func getAppPools() ([]appCmdAppPool, error) {
	if result, err := executeAppCmd("list", "apppool"); err != nil {
		return nil, fmt.Errorf("Failed to get Application Pools: %v", err)
	} else {
		return result.AppPools, nil
	}
}

// Returns if an Application Pool with the given name is started in IIS
func isAppPoolStarted(appPoolName string) (bool, error) {
	if appPool, err := getAppPool(appPoolName, false); err != nil || appPool == nil {
		return false, err
	} else {
		return strings.ToLower(appPool.State) == "started", nil
	}
}

// Starts an Application Pool with the given name in IIS
func startAppPool(appPoolName string) error {
	if isStarted, err := isAppPoolStarted(appPoolName); err != nil || isStarted {
		return err
	}

	if _, err := executeAppCmd("start", "apppool", appPoolName); err != nil {
		return fmt.Errorf("Failed to start Application Pool: %v", err)
	}

	return nil
}

// Stops an Application Pool with the given name in IIS
func stopAppPool(appPoolName string) error {
	if isStarted, err := isAppPoolStarted(appPoolName); err != nil || !isStarted {
		return err
	}

	if _, err := executeAppCmd("stop", "apppool", appPoolName); err != nil {
		return fmt.Errorf("Failed to stop Application Pool: %v", err)
	}

	return nil
}

// Applies the Site bindings
func applySiteBindings(siteName string, bindings []iisBinding) error {
	site, err := getSite(siteName, false)
	if err != nil {
		return err
	}

	currentBindings, err := site.getBindings()
	if err != nil {
		return err
	}

	properties := []string{"set", "site", siteName}

	// Compare current bindings with desired bindings
	// Remove any bindings that exist in both arrays
	var exists bool
	cIndex := 0
	for _, currentBinding := range currentBindings {
		exists = false

		for index, binding := range bindings {
			if binding.IPAddress == "" {
				binding.IPAddress = "*"
			}
			if currentBinding.Type == binding.Type && currentBinding.IPAddress == binding.IPAddress && currentBinding.Port == binding.Port && currentBinding.HostName == binding.HostName {
				exists = true
				bindings[index] = bindings[len(bindings)-1]
				bindings = bindings[:len(bindings)-1]
				break
			}
		}

		if !exists {
			currentBindings[cIndex] = currentBinding
			cIndex++
		}
	}
	currentBindings = currentBindings[:cIndex]

	// Nothing is changed if there are no bindings to update
	if len(currentBindings) == 0 && len(bindings) == 0 {
		return nil
	}

	// Remove any bindings that are not desired
	for _, binding := range currentBindings {
		if binding.Type == "https" {
			bindingInfo, err := getSSLCertBinding(binding.IPAddress, binding.Port)

			if len(bindingInfo) != 0 {
				if err = unbindSSLCert(binding.IPAddress, binding.Port); err != nil {
					return err
				}
			}
		}

		properties = append(properties, fmt.Sprintf("/-bindings.[protocol='%s',bindingInformation='%s:%d:%s']", binding.Type, binding.IPAddress, binding.Port, binding.HostName))
	}

	// Add bindings that are desired
	for _, binding := range bindings {
		if binding.Type == "https" {
			if binding.CertHash == "" {
				return fmt.Errorf("HTTPS binding used, but no cert hash was supplied!")
			}

			bindingInfo, err := getSSLCertBinding(binding.IPAddress, binding.Port)

			if len(bindingInfo) != 0 && bindingInfo["CertificateHash"] != binding.CertHash {
				if err = unbindSSLCert(binding.IPAddress, binding.Port); err != nil {
					return err
				}
			}

			if err = bindSSLCert(siteName, binding.IPAddress, binding.Port, binding.CertHash); err != nil {
				return err
			}
		}

		if binding.IPAddress == "" {
			binding.IPAddress = "*"
		}

		properties = append(properties, fmt.Sprintf("/+bindings.[protocol='%s',bindingInformation='%s:%d:%s']", binding.Type, binding.IPAddress, binding.Port, binding.HostName))
	}

	if _, err := executeAppCmd(properties...); err != nil {
		return fmt.Errorf("Failed to set Site bindings: %v", err)
	}

	return nil
}

// Creates a Site with the given name and applies an IIS exported Site xml if a path is provided
func createSite(siteName string, sitePath string, configPath string) error {
	if exists, err := doesSiteExist(siteName); err != nil || exists {
		return err
	}

	properties := []string{"add", "site", fmt.Sprintf("/name:%s", siteName), fmt.Sprintf("/physicalPath:%s", sitePath)}
	if _, err := executeAppCmdWithInput(configPath, properties...); err != nil {
		return fmt.Errorf("Failed to create Site: %v", err)
	}

	return nil
}

// Deletes a Site with the given name
func deleteSite(siteName string) error {
	if exists, err := doesSiteExist(siteName); err != nil || !exists {
		return err
	}

	if _, err := executeAppCmd("delete", "site", siteName); err != nil {
		return fmt.Errorf("Failed to delete Site: %v", err)
	}

	return nil
}

// Returns if a Site with the given name exists in IIS
func doesSiteExist(siteName string) (bool, error) {
	if site, err := getSite(siteName, false); err != nil || site == nil {
		return false, err
	}

	return true, nil
}

// Returns IISBindings by parsing a Site's bindings string
func (site *appCmdSite) getBindings() ([]iisBinding, error) {
	var currentBindings []iisBinding

	if site.Bindings == "" {
		return currentBindings, nil
	}

	bindings := strings.Split(site.Bindings, ",")

	for _, binding := range bindings {
		var iisBinding iisBinding
		slashIndex := strings.Index(binding, "/")
		iisBinding.Type = binding[:slashIndex]
		bindingInfo := strings.Split(binding[slashIndex+1:], ":")
		iisBinding.IPAddress = bindingInfo[0]
		if port, err := strconv.Atoi(bindingInfo[1]); err != nil {
			return nil, fmt.Errorf("Failed to parse a binding's port")
		} else {
			iisBinding.Port = port
		}
		iisBinding.HostName = bindingInfo[2]

		currentBindings = append(currentBindings, iisBinding)
	}

	return currentBindings, nil
}

// Returns a Site with the given name
func getSite(siteName string, allConfigs bool) (*appCmdSite, error) {
	args := []string{"list", "site", siteName}
	if allConfigs {
		args = append(args, "/config:*")
	}

	if result, err := executeAppCmd(args...); err != nil {
		return nil, fmt.Errorf("Failed to get Site: %v", err)
	} else if len(result.Sites) == 0 {
		return nil, nil
	} else {
		return &result.Sites[0], nil
	}
}

// Returns all Sites that exist in IIS
func getSites() ([]appCmdSite, error) {
	if result, err := executeAppCmd("list", "site"); err != nil {
		return nil, fmt.Errorf("Failed to get Sites: %v", err)
	} else {
		return result.Sites, nil
	}
}

// Returns if a Site with the given name is started in IIS
func isSiteStarted(siteName string) (bool, error) {
	if site, err := getSite(siteName, false); err != nil || site == nil {
		return false, err
	} else {
		return strings.ToLower(site.State) == "started", nil
	}
}

// Starts a Site with the given name in IIS
func startSite(siteName string) error {
	if isRunning, err := isSiteStarted(siteName); err != nil || isRunning {
		return err
	}

	if _, err := executeAppCmd("start", "site", siteName); err != nil {
		return fmt.Errorf("Failed to start Site: %v", err)
	}

	return nil
}

// Stops a Site with the given name in IIS
func stopSite(siteName string) error {
	if isRunning, err := isSiteStarted(siteName); err != nil || !isRunning {
		return err
	}

	if _, err := executeAppCmd("stop", "site", siteName); err != nil {
		return fmt.Errorf("Failed to stop Site: %v", err)
	}

	return nil
}

// Sets a Site's Application Pool to the names given
func applySiteAppPool(siteName string, appPoolName string) error {
	if _, err := executeAppCmd("set", "app", fmt.Sprintf("%s/", siteName), fmt.Sprintf("/applicationPool:%s", appPoolName)); err != nil {
		return fmt.Errorf("Failed to set Site Application Pool: %v", err)
	}

	return nil
}

// Creates an Application Pool and Site with the given configuration
func createWebsite(websiteName string, config *TaskConfig) error {
	mux.Lock()
	defer mux.Unlock()

	if err := createAppPool(websiteName, config.AppPoolConfigPath); err != nil {
		return err
	}
	if err := applyAppPoolIdentity(websiteName, config.AppPoolIdentity); err != nil {
		return err
	}
	if err := applyAppPoolResourceLimit(websiteName, config.AppPoolResources); err != nil {
		return err
	}
	if err := createSite(websiteName, config.Path, config.SiteConfigPath); err != nil {
		return err
	}
	if err := applySiteAppPool(websiteName, websiteName); err != nil {
		return err
	}
	return applySiteBindings(websiteName, config.Bindings)
}

// Deletes an Application Pool and Site with the given name
func deleteWebsite(websiteName string) error {
	if err := deleteSite(websiteName); err != nil {
		return err
	}
	return deleteAppPool(websiteName)
}

// Returns if both Application Pool and Site exist with the given name
func doesWebsiteExist(websiteName string) (bool, error) {
	if exists, err := doesAppPoolExist(websiteName); err != nil || !exists {
		return false, err
	}
	if exists, err := doesSiteExist(websiteName); err != nil || !exists {
		return false, err
	}

	return true, nil
}

// Returns the ProcessIds of a running Application Pool as string slice
func getWebsiteProcessIdsStr(websiteName string) ([]string, error) {
	result, err := executeAppCmd("list", "wp", fmt.Sprintf("/apppool.name:%s", websiteName))
	if err != nil {
		return nil, fmt.Errorf("Failed to get Website Process Ids: %v", err)
	}
	var processIds []string
	for _, wp := range result.WorkerProcesses {
		processIds = append(processIds, wp.Name)
	}

	return processIds, nil
}

// Returns the ProcessIds of a running Application Pool
func getWebsiteProcessIds(websiteName string) ([]int, error) {
	result, err := getWebsiteProcessIdsStr(websiteName)
	if err != nil {
		return nil, err
	}

	var processIds []int
	for _, id := range result {
		newProcessId, err := strconv.Atoi(id)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse Website Process Ids: %v", err)
		}
		processIds = append(processIds, newProcessId)
	}

	return processIds, nil
}

// Gets the WMI CPU and Memory stats of a given website
func getWebsiteStats(websiteName string) (*wmiProcessStats, error) {
	// Get a list of process ids tied to the app pool
	processIds, err := getWebsiteProcessIdsStr(websiteName)
	if err != nil {
		return nil, err
	}

	// No process ids means no stats.
	// IIS sites/app pools can be in a state without an actively running process id.
	if len(processIds) == 0 {
		return &wmiProcessStats{
			WorkingSetPrivate: 0,
			KernelModeTime:    0,
			UserModeTime:      0,
		}, nil
	}

	// Query WMI for cpu stats with the given process ids
	var wmiProcesses []wmiProcessStats
	if err := wmi.Query(fmt.Sprintf("SELECT KernelModeTime,UserModeTime FROM Win32_Process WHERE ProcessID=%s", strings.Join(processIds, "OR ProcessID=")), &wmiProcesses); err != nil {
		return nil, err
	}

	// Sum up all cpu stats
	var stats wmiProcessStats
	for _, process := range wmiProcesses {
		stats.KernelModeTime += process.KernelModeTime
		stats.UserModeTime += process.UserModeTime
	}

	// Query WMI for memory stats with the given process ids
	// We are only using the WorkingSetPrivate for our memory to better align the Windows Task Manager and the RSS field nomad is expecting
	if err := wmi.Query(fmt.Sprintf("SELECT WorkingSetPrivate FROM Win32_PerfFormattedData_PerfProc_Process WHERE IDProcess=%s", strings.Join(processIds, "OR IDProcess=")), &wmiProcesses); err != nil {
		return nil, err
	}

	// Sum up all memory stats
	for _, process := range wmiProcesses {
		stats.WorkingSetPrivate += process.WorkingSetPrivate
	}

	// Need to multiply cpu stats by one hundred to align with nomad method CpuStats.Percent's expected decimal placement
	stats.KernelModeTime *= 100
	stats.UserModeTime *= 100
	return &stats, nil
}

func isWebsiteStarted(websiteName string) (bool, error) {
	if isStarted, err := isAppPoolStarted(websiteName); err != nil || !isStarted {
		return false, err
	}
	if isStarted, err := isSiteStarted(websiteName); err != nil || !isStarted {
		return false, err
	}

	return true, nil
}

// Returns if the Application Pool has running processes or both Application Pool and Site are started with the given name
func isWebsiteRunning(websiteName string) (bool, error) {
	processIds, err := getWebsiteProcessIdsStr(websiteName)
	if err != nil {
		return false, err
	}
	if len(processIds) != 0 {
		return true, nil
	}

	if isRunning, err := isWebsiteStarted(websiteName); err != nil || !isRunning {
		return false, err
	}

	return true, nil
}

// Starts both Application Pool and Site with the given name
func startWebsite(websiteName string) error {
	if err := startAppPool(websiteName); err != nil {
		return err
	}
	return startSite(websiteName)
}

// Stops both Application Pool and Site with the given name
func stopWebsite(websiteName string) error {
	if err := stopSite(websiteName); err != nil {
		return err
	}
	return stopAppPool(websiteName)
}

func getNetshIP(ipAddress string) string {
	if ipAddress != "" && ipAddress != "*" {
		return ipAddress
	} else {
		return "0.0.0.0"
	}
}

// Binds an appid, ip address, and port to a hash of a pre-existing certificate in the cert store for https protocol IIS binding with netsh
func bindSSLCert(appID string, ipAddress string, port int, hash string) error {
	if info, err := getSSLCertBinding(ipAddress, port); err != nil {
		return err
	} else if info["CertificateHash"] == hash {
		return nil
	}

	cmd := exec.Command(`C:\Windows\System32\netsh.exe`, "http", "add", "sslcert", fmt.Sprintf("ipport=%s:%d", getNetshIP(ipAddress), port), fmt.Sprintf("certhash=%s", hash), fmt.Sprintf("appid={%s}", appID))

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Failed to install cert! %+v", err)
	}

	return nil
}

// Gets sslcert binding details from an ip address and port with netsh.
func getSSLCertBinding(ipAddress string, port int) (map[string]string, error) {

	cmd := exec.Command(`C:\Windows\System32\netsh.exe`, "http", "show", "sslcert", fmt.Sprintf("%s:%d", getNetshIP(ipAddress), port))

	if out, err := cmd.Output(); err != nil {
		// Only ignore errors for not being able to find the file specified. SSLBinding doesn't exist in that case
		if !strings.Contains(string(out), "The system cannot find the file specified") {
			return nil, fmt.Errorf("Failed to read imported certificate! %+v", err)
		}
		return nil, nil
	} else {
		result := make(map[string]string)
		count := 0
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			count++
			if count < 3 {
				continue
			}
			line := scanner.Text()
			if strings.Contains(line, ":") {
				split := strings.Split(line, ":")

				space := regexp.MustCompile(`\s+`)
				key := space.ReplaceAllString(split[0], "")
				result[key] = strings.TrimSpace(split[1])
			}
		}

		return result, nil
	}
}

// Removes ip address and port sslcert binding with netsh
func unbindSSLCert(ipAddress string, port int) error {
	if info, err := getSSLCertBinding(ipAddress, port); err != nil || len(info) == 0 {
		return err
	}

	cmd := exec.Command(`C:\Windows\System32\netsh.exe`, "http", "delete", "sslcert", fmt.Sprintf("ipport=%s:%d", getNetshIP(ipAddress), port))

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Failed to uninstall cert! %+v", err)
	}

	return nil
}
