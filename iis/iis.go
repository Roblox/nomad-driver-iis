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
)

type AppCmdAppPool struct {
	Name           string     `xml:"APPPOOL.NAME,attr"`
	PipelineMode   string     `xml:"PipelineMode,attr"`
	RuntimeVersion string     `xml:"RuntimeVersion,attr"`
	State          string     `xml:"state,attr"`
	Add            AppPoolAdd `xml:"add"`
}

type AppPoolAdd struct {
	Name         string              `xml:"name,attr"`
	QueueLength  int                 `xml:"queueLength,attr"`
	AutoStart    bool                `xml:"autoStart,attr"`
	ProcessModel AppPoolProcessModel `xml:"processModel"`
}

type AppPoolProcessModel struct {
	IdentityType string `xml:"identityType,attr"`
	Password     string `xml:"password,attr"`
	Username     string `xml:"userName,attr"`
}

type AppCmdMessage struct {
	Message string `xml:"message,attr"`
}

type AppCmdResult struct {
	AppPools        []AppCmdAppPool `xml:"APPPOOL"`
	Errors          []AppCmdMessage `xml:"ERROR"`
	Sites           []AppCmdSite    `xml:"SITE"`
	Statuses        []AppCmdMessage `xml:"STATUS"`
	WorkerProcesses []AppCmdWP      `xml:"WP"`
	XMLName         xml.Name        `xml:"appcmd"`
}

type AppCmdSite struct {
	Bindings string `xml:"bindings,attr"`
	ID       int    `xml:"SISTE.ID,attr"`
	Name     string `xml:"SITE.NAME,attr"`
	State    string `xml:"state,attr"`
	Site     Site   `xml:"site"`
}

type Site struct {
	Name        string          `xml:"name,attr"`
	ID          string          `xml:"id,attr"`
	Application SiteApplication `xml:"application"`
}

type SiteApplication struct {
	Path            string     `xml:"path,attr"`
	ApplicationPool string     `xml:"applicationPool,attr"`
	VDirs           []SiteVDir `xml:"virtualDirectory"`
}

type SiteVDir struct {
	Path         string `xml:"path,attr"`
	PhysicalPath string `xml:"physicalPath,attr"`
}

type AppCmdWP struct {
	AppPoolName string `xml:"APPPOOL.NAME,attr"`
	Name        string `xml:"WP.NAME,attr"`
}

type IISAppPoolIdentity struct {
	Identity string
	Password string
	Username string
}

type IISBinding struct {
	CertHash     string
	HostName     string
	IPAddress    string
	Port         int
	ResourcePort string
	Type         string
}

type IISClient struct {
	AllConfigs bool
}

type IISWebsiteConfig struct {
	AppPoolConfigPath string
	AppPoolIdentity   IISAppPoolIdentity
	Bindings          []IISBinding
	Path              string
	SiteConfigPath    string
}

// IIS

func (c *IISClient) GetVersion() (string, error) {
	var iisVersion string
	cmd := exec.Command("cmd", "/C", `wmic datafile where name='C:\\Windows\\System32\\inetsrv\\InetMgr.exe' get version`)
	if out, err := cmd.Output(); err != nil {
		return iisVersion, fmt.Errorf("Failed to determine version: %v", err)
	} else {
		iisVersion = strings.Fields(string(out))[1]
	}
	return iisVersion, nil
}

func (c *IISClient) IsIISRunning() bool {
	var iisState bool = false
	cmd := exec.Command(`C:\Windows\System32\sc.exe`, "query", "w3svc")
	if out, err := cmd.Output(); err != nil {
		return iisState
	} else {
		iisState, _ = regexp.MatchString(`STATE.*:.*4.*RUNNING`, string(out))
	}
	return iisState
}

func (c *IISClient) PurgeIIS() error {
	sites, err := c.GetSites()
	if err != nil {
		return err
	}
	appPools, err := c.GetAppPools()
	if err != nil {
		return err
	}

	for _, site := range sites {
		if err = c.DeleteSite(site.Name); err != nil {
			return err
		}
	}
	for _, appPool := range appPools {
		if err = c.DeleteAppPool(appPool.Name); err != nil {
			return err
		}
	}
	return nil
}

func (c *IISClient) StartIIS() error {
	if c.IsIISRunning() {
		return nil
	}

	cmd := exec.Command(`C:\Windows\System32\sc.exe`, "start", "w3svc")
	if _, err := cmd.Output(); err != nil {
		return err
	}
	return nil
}

func (c *IISClient) StopIIS() error {
	if !c.IsIISRunning() {
		return nil
	}

	cmd := exec.Command(`C:\Windows\System32\sc.exe`, "stop", "w3svc")
	if _, err := cmd.Output(); err != nil {
		return err
	}
	return nil
}

// APP POOL

func (c *IISClient) ApplyAppPoolSettings(appPoolName string, appPoolIdentity IISAppPoolIdentity) error {
	var result AppCmdResult
	properties := []string{"set", "config", "/section:applicationPools", "/xml"}

	if appPoolIdentity.Identity != "" {
		properties = append(properties, fmt.Sprintf("/[name='%s'].processModel.identityType:%s", appPoolName, appPoolIdentity.Identity))
	}

	if appPoolIdentity.Identity == "SpecificUser" && appPoolIdentity.Username != "" && appPoolIdentity.Password != "" {
		properties = append(properties, fmt.Sprintf("/[name='%s'].processModel.userName:%s", appPoolName, appPoolIdentity.Username))
		properties = append(properties, fmt.Sprintf("/[name='%s'].processModel.password:%s", appPoolName, appPoolIdentity.Password))
	}

	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, properties...)
	out, err := cmd.CombinedOutput()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return fmt.Errorf("Failed to set Application Pool settings: %v", result.Errors[0].Message)
	} else if err != nil {
		return fmt.Errorf("Failed to set Application Pool settings: %v", string(out))
	}

	return nil
}

func (c *IISClient) CreateAppPool(appPoolName string, configPath string) error {
	if c.DoesAppPoolExist(appPoolName) {
		return nil
	}

	var result AppCmdResult

	properties := []string{"/C", `C:\Windows\System32\inetsrv\APPCMD.exe`, "add", "apppool", "/xml", fmt.Sprintf("/name:%s", appPoolName)}

	if configPath != "" {
		properties = append(properties, fmt.Sprintf("/in<%s", configPath))
	}

	cmd := exec.Command("cmd", properties...)
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return fmt.Errorf("Failed to create Application Pool: %v", result.Errors[0].Message)
	} else if err != nil {
		return fmt.Errorf("Failed to create Application Pool: %v", string(out))
	}

	return nil
}

func (c *IISClient) DeleteAppPool(appPoolName string) error {
	if !c.DoesAppPoolExist(appPoolName) {
		return nil
	}

	var result AppCmdResult
	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "delete", "apppool", appPoolName, "/xml")
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return fmt.Errorf("Failed to delete Application Pool: %v", result.Errors[0].Message)
	} else if err != nil {
		return fmt.Errorf("Failed to delete Application Pool: %v", string(out))
	}

	return nil
}

func (c *IISClient) DoesAppPoolExist(appPoolName string) bool {
	if _, err := c.GetAppPool(appPoolName); err != nil {
		return false
	}

	return true
}

func (c *IISClient) GetAppPool(appPoolName string) (AppCmdAppPool, error) {
	var result AppCmdResult
	var appPool AppCmdAppPool

	config := ""
	if c.AllConfigs {
		config = "/config:*"
	}

	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "list", "apppool", appPoolName, config, "/xml")
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return appPool, fmt.Errorf("Failed to get AppPool: %v", result.Errors[0].Message)
	} else if err != nil {
		return appPool, fmt.Errorf("Failed to get AppPool!")
	} else if len(result.AppPools) == 0 {
		return appPool, fmt.Errorf("Failed to find AppPool")
	}

	appPool = result.AppPools[0]

	return appPool, nil
}

func (c *IISClient) GetAppPools() ([]AppCmdAppPool, error) {
	var result AppCmdResult

	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "list", "apppool", "/xml")
	out, _ := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return result.AppPools, fmt.Errorf("Failed to list Application Pools: %v", result.Errors[0].Message)
	}

	return result.AppPools, nil
}

func (c *IISClient) IsAppPoolRunning(appPoolName string) bool {
	if appPool, err := c.GetAppPool(appPoolName); err != nil {
		return false
	} else {
		return strings.ToLower(appPool.State) == "started"
	}
}

func (c *IISClient) StartAppPool(appPoolName string) error {
	if c.IsAppPoolRunning(appPoolName) {
		return nil
	}

	var result AppCmdResult
	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "start", "apppool", appPoolName, "/xml")
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return fmt.Errorf("Failed to start Application Pool: %v", result.Errors[0].Message)
	} else if err != nil {
		return fmt.Errorf("Failed to start Application Pool: %v", string(out))
	}

	return nil
}

func (c *IISClient) StopAppPool(appPoolName string) error {
	if !c.IsAppPoolRunning(appPoolName) {
		return nil
	}

	var result AppCmdResult
	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "stop", "apppool", appPoolName, "/xml")
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return fmt.Errorf("Failed to stop Application Pool: %v", result.Errors[0].Message)
	} else if err != nil {
		return fmt.Errorf("Failed to stop Application Pool: %v", string(out))
	}
	return nil
}

// SITE

func (c *IISClient) ApplySiteBindings(siteName string, bindings []IISBinding) error {
	var result AppCmdResult
	site, err := c.GetSite(siteName)
	if err != nil {
		return err
	}

	currentBindings, err := site.GetBindings()
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

	if len(currentBindings) == 0 && len(bindings) == 0 {
		return nil
	}

	// Remove any bindings that are not desired
	for _, binding := range currentBindings {
		if binding.Type == "https" {
			bindingInfo, err := c.GetSSLCertBinding(binding.IPAddress, binding.Port)

			if len(bindingInfo) != 0 {
				if err = c.UnbindSSLCert(binding.IPAddress, binding.Port); err != nil {
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

			bindingInfo, err := c.GetSSLCertBinding(binding.IPAddress, binding.Port)

			if len(bindingInfo) != 0 && bindingInfo["CertificateHash"] != binding.CertHash {
				if err = c.UnbindSSLCert(binding.IPAddress, binding.Port); err != nil {
					return err
				}
			}

			if err = c.BindSSLCert(siteName, binding.IPAddress, binding.Port, binding.CertHash); err != nil {
				return err
			}
		}

		if binding.IPAddress == "" {
			binding.IPAddress = "*"
		}

		properties = append(properties, fmt.Sprintf("/+bindings.[protocol='%s',bindingInformation='%s:%d:%s']", binding.Type, binding.IPAddress, binding.Port, binding.HostName))
	}

	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, properties...)
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return fmt.Errorf("Failed to set Site settings: %v", result.Errors[0].Message)
	} else if err != nil {
		return fmt.Errorf("Failed to set Site settings: %v", string(out))
	}

	return nil
}

func (c *IISClient) CreateSite(siteName string, sitePath string, configPath string) error {
	if c.DoesSiteExist(siteName) {
		return nil
	}

	var result AppCmdResult
	properties := []string{"/C", `C:\Windows\System32\inetsrv\APPCMD.exe`, "add", "site", "/xml", fmt.Sprintf("/name:%s", siteName), fmt.Sprintf("/physicalPath:%s", sitePath)}

	if configPath != "" {
		properties = append(properties, fmt.Sprintf("/in<%s", configPath))
	}

	cmd := exec.Command("cmd", properties...)
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return fmt.Errorf("Failed to create Site: %v", result.Errors[0].Message)
	} else if err != nil {
		return fmt.Errorf("Failed to create Site: %v", string(out))
	}

	return nil
}

func (c *IISClient) DeleteSite(siteName string) error {
	if !c.DoesSiteExist(siteName) {
		return nil
	}

	var result AppCmdResult
	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "delete", "site", siteName, "/xml")
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return fmt.Errorf("Failed to delete Site: %v", result.Errors[0].Message)
	} else if err != nil {
		return fmt.Errorf("Failed to delete Site: %v", string(out))
	}

	return nil
}

func (c *IISClient) DoesSiteExist(siteName string) bool {
	if _, err := c.GetSite(siteName); err != nil {
		return false
	}

	return true
}

func (site *AppCmdSite) GetBindings() ([]IISBinding, error) {
	var currentBindings []IISBinding

	if site.Bindings == "" {
		return currentBindings, nil
	}

	bindings := strings.Split(site.Bindings, ",")

	for _, binding := range bindings {
		var iisBinding IISBinding
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

func (c *IISClient) GetSite(siteName string) (AppCmdSite, error) {
	var result AppCmdResult
	var site AppCmdSite

	config := ""
	if c.AllConfigs {
		config = "/config:*"
	}

	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "list", "site", siteName, config, "/xml")
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return site, fmt.Errorf("Failed to get Site: %v", result.Errors[0].Message)
	} else if err != nil {
		return site, fmt.Errorf("Failed to get Site!")
	} else if len(result.Sites) == 0 {
		return site, fmt.Errorf("Failed to find Site!")
	}

	site = result.Sites[0]

	return site, nil
}

func (c *IISClient) GetSites() ([]AppCmdSite, error) {
	var result AppCmdResult

	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "list", "site", "/xml")
	out, _ := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return result.Sites, fmt.Errorf("Failed to list Sites: %v", result.Errors[0].Message)
	}

	return result.Sites, nil
}

func (c *IISClient) IsSiteRunning(siteName string) bool {
	if site, err := c.GetSite(siteName); err != nil {
		return false
	} else {
		return strings.ToLower(site.State) == "started"
	}
}

func (c *IISClient) StartSite(siteName string) error {
	if c.IsSiteRunning(siteName) {
		return nil
	}

	var result AppCmdResult

	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "start", "site", siteName, "/xml")
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return fmt.Errorf("Failed to start Site: %v", result.Errors[0].Message)
	} else if err != nil {
		return fmt.Errorf("Failed to start Site: %v", string(out))
	}

	return nil
}

func (c *IISClient) StopSite(siteName string) error {
	if !c.IsSiteRunning(siteName) {
		return nil
	}

	var result AppCmdResult
	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "stop", "site", siteName, "/xml")
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return fmt.Errorf("Failed to stop Site: %v", result.Errors[0].Message)
	} else if err != nil {
		return fmt.Errorf("Failed to stop Site: %v", string(out))
	}

	return nil
}

// APP

func (c *IISClient) ApplyAppSettings(siteName string) error {
	var result AppCmdResult
	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "set", "app", fmt.Sprintf("%s/", siteName), fmt.Sprintf("/applicationPool:%s", siteName), "/xml")
	out, err := cmd.Output()
	xml.Unmarshal(out, &result)

	if len(result.Errors) != 0 {
		return fmt.Errorf("Failed to set Application settings: %v", result.Errors[0].Message)
	} else if err != nil {
		return fmt.Errorf("Failed to set Application settings: %v", string(out))
	}

	return nil
}

// WEBSITE

func (c *IISClient) CreateWebsite(webSiteName string, config IISWebsiteConfig) error {
	if err := c.CreateAppPool(webSiteName, config.AppPoolConfigPath); err != nil {
		return err
	}
	if err := c.ApplyAppPoolSettings(webSiteName, config.AppPoolIdentity); err != nil {
		return err
	}

	if err := c.CreateSite(webSiteName, config.Path, config.SiteConfigPath); err != nil {
		return err
	}
	if err := c.ApplyAppSettings(webSiteName); err != nil {
		return err
	}
	if err := c.ApplySiteBindings(webSiteName, config.Bindings); err != nil {
		return err
	}

	return nil
}

func (c *IISClient) DeleteWebsite(webSiteName string) error {
	if err := c.DeleteSite(webSiteName); err != nil {
		return err
	}
	if err := c.DeleteAppPool(webSiteName); err != nil {
		return err
	}
	return nil
}

func (c *IISClient) DoesWebsiteExist(webSiteName string) bool {
	return c.DoesAppPoolExist(webSiteName) && c.DoesSiteExist(webSiteName)
}

func (c *IISClient) GetWebsiteProcessIds(webSiteName string) []int {
	var result AppCmdResult
	var processIds []int

	cmd := exec.Command(`C:\Windows\System32\inetsrv\APPCMD.exe`, "list", "wp", fmt.Sprintf("/apppool.name:%s", webSiteName), "/xml")
	out, err := cmd.Output()
	if err != nil {
		return processIds
	}
	xml.Unmarshal(out, &result)

	for _, wp := range result.WorkerProcesses {
		newProcessID, err := strconv.Atoi(wp.Name)
		if err == nil {
			processIds = append(processIds, newProcessID)
		}
	}

	return processIds
}

func (c *IISClient) IsWebsiteRunning(webSiteName string) bool {
	return c.IsAppPoolRunning(webSiteName) && c.IsSiteRunning(webSiteName)
}

func (c *IISClient) StartWebsite(webSiteName string) error {
	if err := c.StartAppPool(webSiteName); err != nil {
		return err
	}
	if err := c.StartSite(webSiteName); err != nil {
		return err
	}

	return nil
}

func (c *IISClient) StopWebsite(webSiteName string) error {
	if err := c.StopSite(webSiteName); err != nil {
		return err
	}
	if err := c.StopAppPool(webSiteName); err != nil {
		return err
	}

	return nil
}

// CERTIFICATES

func (c *IISClient) BindSSLCert(appID string, ipAddress string, port int, hash string) error {
	if info, err := c.GetSSLCertBinding(ipAddress, port); err != nil {
		return err
	} else if len(info) != 0 && info["CertificateHash"] == hash {
		return nil
	}

	netshIPAddress := "0.0.0.0"
	if ipAddress != "" && ipAddress != "*" {
		netshIPAddress = ipAddress
	}

	cmd := exec.Command(`C:\Windows\System32\netsh.exe`, "http", "add", "sslcert", fmt.Sprintf("ipport=%s:%d", netshIPAddress, port), fmt.Sprintf("certhash=%s", hash), fmt.Sprintf("appid={%s}", appID))

	_, err := cmd.Output()
	if err != nil {
		fmt.Println(cmd)
		return fmt.Errorf("Failed to install cert! %+v", err)
	}

	return nil
}

func (c *IISClient) GetSSLCertBinding(ipAddress string, port int) (map[string]string, error) {
	netshIPAddress := "0.0.0.0"
	if ipAddress != "" && ipAddress != "*" {
		netshIPAddress = ipAddress
	}

	var result map[string]string
	cmd := exec.Command(`C:\Windows\System32\netsh.exe`, "http", "show", "sslcert", fmt.Sprintf("%s:%d", netshIPAddress, port))
	out, err := cmd.Output()

	if err != nil {
		if !strings.Contains(string(out), "The system cannot find the file specified") {
			return result, fmt.Errorf("Failed to read imported certificate! %+v", err)
		}
	}

	result = make(map[string]string)
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

func (c *IISClient) UnbindSSLCert(ipAddress string, port int) error {
	if info, err := c.GetSSLCertBinding(ipAddress, port); err != nil {
		return err
	} else if len(info) == 0 {
		return nil
	}

	netshIPAddress := "0.0.0.0"
	if ipAddress != "" && ipAddress != "*" {
		netshIPAddress = ipAddress
	}

	cmd := exec.Command(`C:\Windows\System32\netsh.exe`, "http", "delete", "sslcert", fmt.Sprintf("ipport=%s:%d", netshIPAddress, port))

	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Failed to uninstall cert! %+v", err)
	}

	return nil
}
