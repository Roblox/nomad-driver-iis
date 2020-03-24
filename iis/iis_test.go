package iis

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	iis "github.com/roblox/nomad-driver-iis/iis"
	"github.com/stretchr/testify/assert"
)

var (
	guid = "d42d7b18-691b-409a-94fd-4259a2b7e066"
	hash = "854d57551e79656159a0081054fbc08c6c648f86"

	iisClient *iis.IISClient
)

func init() {
	iisClient = &iis.IISClient{
		AllConfigs: true,
	}
}
func TestIISVersion(t *testing.T) {
	if iisClient == nil {
		t.Fatal("IIS client failed to initialize")
	}

	version, err := iisClient.GetVersion()
	if err != nil {
		t.Fatalf("Error getting version: %+v", err)
	}

	match, _ := regexp.MatchString(`^[0-9]*\.[0-9]*\.[0-9]*\.[[0-9]*$`, version)
	if !match {
		t.Fatal("Version returned does not match regex")
	}
}

func TestIISRunning(t *testing.T) {
	if iisClient == nil {
		t.Fatal("IIS client failed to initialize")
	}

	if err := iisClient.StopIIS(); err != nil {
		t.Fatal("Error trying to stop IIS!")
	}

	c1 := make(chan bool, 1)
	go func() {
		isRunning := true

		for isRunning {
			isRunning = iisClient.IsIISRunning()
			time.Sleep(1 * time.Second)
		}

		c1 <- isRunning
	}()

	// Listen on our channel AND a timeout channel - which ever happens first.
	select {
	case isRunning := <-c1:
		if isRunning {
			t.Fatal("IIS did not stop!")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout: IIS failed to stop in a reasonable time!")
	}

	if err := iisClient.StartIIS(); err != nil {
		t.Fatal("Error trying to start IIS!")
	}

	go func() {
		isRunning := false

		for !isRunning {
			isRunning = iisClient.IsIISRunning()
			time.Sleep(1 * time.Second)
		}

		c1 <- isRunning
	}()

	// Listen on our channel AND a timeout channel - which ever happens first.
	select {
	case isRunning := <-c1:
		if !isRunning {
			t.Fatal("IIS did not start!")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout: IIS failed to start in a reasonable time!")
	}
}

func TestSSLBinding(t *testing.T) {
	if iisClient == nil {
		t.Fatal("IIS client failed to initialize")
	}

	if err := iisClient.UnbindSSLCert("0.0.0.0", 8081); err != nil {
		t.Fatalf("Error unbinding ssl cert: %+v", err)
	}

	bindingInfo, err := iisClient.GetSSLCertBinding("0.0.0.0", 8081)
	if err != nil {
		t.Fatalf("Error getting ssl cert binding: %+v", err)
	}

	if len(bindingInfo) != 0 && bindingInfo["CertificateHash"] == hash {
		t.Fatalf("SSL Cert binding exist after unbind!")
	}

	if err := iisClient.BindSSLCert(guid, "0.0.0.0", 8081, hash); err != nil {
		t.Fatalf("Error unbinding ssl cert: %+v", err)
	}

	bindingInfo, err = iisClient.GetSSLCertBinding("0.0.0.0", 8081)
	if err != nil {
		t.Fatalf("Error getting ssl cert binding: %+v", err)
	}

	if err := iisClient.UnbindSSLCert("0.0.0.0", 8081); err != nil {
		t.Fatalf("Error unbinding ssl cert: %+v", err)
	}

	bindingInfo, err = iisClient.GetSSLCertBinding("0.0.0.0", 8081)
	if err != nil {
		t.Fatalf("Error getting ssl cert binding: %+v", err)
	}

	if len(bindingInfo) != 0 {
		t.Fatal("SSL Cert binding exist after unbind!")
	}
}

func TestWebsite(t *testing.T) {
	assert := assert.New(t)
	if iisClient == nil {
		t.Fatal("IIS client failed to initialize")
	}
	if err := iisClient.PurgeIIS(); err != nil {
		t.Fatal("Error purging: ", err)
	}

	config := iis.IISWebsiteConfig{
		Path: "C:\\inetpub\\wwwroot",
		AppPoolIdentity: iis.IISAppPoolIdentity{
			Identity: "SpecificUser",
			Username: "vagrant",
			Password: "vagrant",
		},
		Bindings: []iis.IISBinding{
			{Type: "http", Port: 8080},
			{Type: "https", Port: 8081, CertHash: hash},
		},
		AppPoolConfigPath: "C:\\vagrant\\vagrant\\testapppool.xml",
		SiteConfigPath:    "C:\\vagrant\\vagrant\\testsite.xml",
	}

	if iisClient.DoesWebsiteExist(guid) {
		if err := iisClient.DeleteWebsite(guid); err != nil {
			t.Fatalf("Error deleting website: %+v", err)
		}
	}

	err := iisClient.CreateWebsite(guid, config)
	if err != nil {
		t.Fatalf("Error creating website: %+v", err)
	}

	err = iisClient.CreateWebsite(guid, config)
	if err != nil {
		t.Fatalf("Error creating website 2: %+v", err)
	}

	// Verify settings
	if appPool, err := iisClient.GetAppPool(guid); err != nil {
		t.Fatal("Failed to get Site info!")
	} else {
		assert.Equal(config.AppPoolIdentity.Identity, appPool.Add.ProcessModel.IdentityType, "AppPool Identity Type doesn't match!")
		assert.Equal(config.AppPoolIdentity.Username, appPool.Add.ProcessModel.Username, "AppPool Identity Username doesn't match!")
		assert.Equal(config.AppPoolIdentity.Password, appPool.Add.ProcessModel.Password, "AppPool Identity Password doesn't match!")
		assert.Equal("", appPool.RuntimeVersion, "AppPool RuntimeVersion doesn't match!")
		assert.Equal("Integrated", appPool.PipelineMode, "AppPool PipelineMode doesn't match!")
	}

	if site, err := iisClient.GetSite(guid); err != nil {
		t.Fatal("Failed to get Site info!")
	} else {
		assert.Equal(site.Site.Application.VDirs[0].PhysicalPath, config.Path, "Website path doesn't match desired path from config!")
	}

	if err := iisClient.StartWebsite(guid); err != nil {
		t.Fatalf("Error starting website: %+v", err)
	}

	if err := iisClient.StartWebsite(guid); err != nil {
		t.Fatalf("Error starting website 2: %+v", err)
	}

	if !iisClient.IsWebsiteRunning(guid) {
		t.Fatalf("Website is not started!")
	}

	if err := iisClient.StopWebsite(guid); err != nil {
		t.Fatalf("Error stopping website: %+v", err)
	}

	if err := iisClient.StopWebsite(guid); err != nil {
		t.Fatalf("Error stopping website 2: %+v", err)
	}

	if iisClient.IsWebsiteRunning(guid) {
		t.Fatalf("Website is not stopped!")
	}

	if err = iisClient.DeleteWebsite(guid); err != nil {
		t.Fatalf("Error deleting website: %+v", err)
	}

	if err = iisClient.DeleteWebsite(guid); err != nil {
		t.Fatalf("Error deleting website 2: %+v", err)
	}

	if iisClient.DoesWebsiteExist(guid) {
		t.Fatal("Website exists after deletion!")
	}
}

func doBindingsMatch(expected []iis.IISBinding, actual []iis.IISBinding) bool {
	if len(expected) != len(actual) {
		fmt.Println(fmt.Sprintf("Expected %d bindings, but got %d", len(expected), len(actual)))
		return false
	} else {
		exists := false
		for _, expectedBinding := range expected {
			exists = false
			for _, actualBinding := range actual {
				if expectedBinding.Type == actualBinding.Type &&
					expectedBinding.IPAddress == actualBinding.IPAddress &&
					expectedBinding.HostName == actualBinding.HostName &&
					expectedBinding.Port == actualBinding.Port {
					exists = true
					break
				}
			}
			if !exists {
				fmt.Println("Doesn't Exist: ", expectedBinding)
				return false
			}
		}
	}

	return true
}

func TestSiteBinding(t *testing.T) {

	if iisClient == nil {
		t.Fatal("IIS client failed to initialize")
	}
	if err := iisClient.PurgeIIS(); err != nil {
		t.Fatal("Error purging: ", err)
	}

	var site iis.AppCmdSite
	var err error

	if err = iisClient.CreateSite(guid, "C:\\inetpub\\wwwroot", ""); err != nil {
		t.Fatalf("Failed to create Site: %+v", err)
	}

	bindings := []iis.IISBinding{
		{Type: "http", Port: 8080, IPAddress: "*"},
		{Type: "https", Port: 8081, IPAddress: "*", CertHash: hash},
	}

	if err = iisClient.ApplySiteBindings(guid, bindings); err != nil {
		t.Fatal(err)
	}

	if site, err = iisClient.GetSite(guid); err != nil {
		t.Fatal(err)
	}

	if actualBindings, err := site.GetBindings(); err != nil {
		t.Fatal(err)
	} else if !doBindingsMatch(bindings, actualBindings) {
		t.Fatal("Expected and Actual bindings do not match!")
	}

	bindings = []iis.IISBinding{
		{Type: "http", Port: 8080, IPAddress: "*"},
		{Type: "http", Port: 8081, IPAddress: "*"},
		{Type: "https", Port: 8082, IPAddress: "172.17.8.101", HostName: "test.com", CertHash: hash},
	}

	if err = iisClient.ApplySiteBindings(guid, bindings); err != nil {
		t.Fatal(err)
	}

	if site, err = iisClient.GetSite(guid); err != nil {
		t.Fatal(err)
	}

	if actualBindings, err := site.GetBindings(); err != nil {
		t.Fatal(err)
	} else if !doBindingsMatch(bindings, actualBindings) {
		t.Fatal("Expected and Actual bindings do not match!")
	}

	bindings = []iis.IISBinding{}

	if err = iisClient.ApplySiteBindings(guid, bindings); err != nil {
		t.Fatal(err)
	}

	if site, err = iisClient.GetSite(guid); err != nil {
		t.Fatal(err)
	}

	if actualBindings, err := site.GetBindings(); err != nil {
		t.Fatal(err)
	} else if !doBindingsMatch(bindings, actualBindings) {
		t.Fatal("Expected and Actual bindings do not match!")
	}

	if err = iisClient.DeleteSite(guid); err != nil {
		t.Fatal(err)
	}
}
