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

// This is a test file for iis.go and IIS on a Windows Server
// All tests are using to execute the iis function which directly communicate with various executables of Windows (sc, netsh, and appcmd)
// These tests ensure the functionality of the code being used by the nomad handle/driver will properly change iis as needed

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	guid = "d42d7b18-691b-409a-94fd-4259a2b7e066"
	hash = "854d57551e79656159a0081054fbc08c6c648f86"
)

// Test the fingerprinting ability of getVersion to ensure it is outputing the proper version format of IIS
func TestIISVersion(t *testing.T) {
	version, err := getVersion()
	if err != nil {
		t.Fatal(err)
	}

	if match, err := regexp.MatchString(`^[0-9]*\.[0-9]*\.[0-9]*\.[[0-9]*$`, version); err != nil {
		t.Fatal(err)
	} else if !match {
		t.Fatal("Version returned does not match regex")
	}
}

// Test to ensure IIS functions for altering IIS's state works for other functional/integration tests
func TestIISRunning(t *testing.T) {
	if err := stopIIS(); err != nil {
		t.Fatal(err)
	}

	// Wait for IIS running state to return as false, or timeout
	c1 := make(chan bool, 1)
	go func() {
		isRunning := true

		for isRunning {
			if running, err := isIISRunning(); err != nil {
				t.Fatal(err)
			} else {
				isRunning = running
			}
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

	if err := startIIS(); err != nil {
		t.Fatal("Error trying to start IIS!")
	}

	// Wait for IIS running state to return as true, or timeout
	go func() {
		isRunning := false

		for !isRunning {
			if running, err := isIISRunning(); err != nil {
				t.Fatal(err)
			} else {
				isRunning = running
			}
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

// Test SSL Binding functionalility with netsh
func TestSSLBinding(t *testing.T) {
	ipAddress := "0.0.0.0"
	port := 8081
	// Unbind for fresh start
	if err := unbindSSLCert(ipAddress, port); err != nil {
		t.Fatal(err)
	}

	// Check to see if unbinding the port was actually applied
	if bindingInfo, err := getSSLCertBinding(ipAddress, port); err != nil {
		t.Fatal(err)
	} else if bindingInfo != nil {
		t.Fatalf("SSL Cert binding exist after unbind!")
	}

	// Bind the ip:port
	if err := bindSSLCert(guid, ipAddress, port, hash); err != nil {
		t.Fatal(err)
	}
	// Bind idempotency test
	if err := bindSSLCert(guid, ipAddress, port, hash); err != nil {
		t.Fatal(err)
	}

	// Verify that an ssl binding exists for the ip and port
	if bindingInfo, err := getSSLCertBinding(ipAddress, port); err != nil {
		t.Fatal(err)
	} else if bindingInfo == nil {
		t.Fatal("SSL Cert binding doesn't exist after bind!")
	} else {
		assert.Equal(t, hash, bindingInfo["CertificateHash"], "Bound SSL Cert Hash doesn't match!")
	}

	// Unbind test
	if err := unbindSSLCert(ipAddress, port); err != nil {
		t.Fatal(err)
	}
	// Unbind idempotency test
	if err := unbindSSLCert(ipAddress, port); err != nil {
		t.Fatal(err)
	}

	// Verify ssl cert was unbound to the given ip:port
	if bindingInfo, err := getSSLCertBinding(ipAddress, port); err != nil {
		t.Fatal(err)
	} else if bindingInfo != nil {
		t.Fatal("SSL Cert binding exists after unbind!")
	}
}

// Helper function for verify iis bindings match
func doBindingsMatchSite(t *testing.T, expected []iisBinding, siteName string) bool {
	site, err := getSite(guid, true)
	if err != nil {
		t.Fatal(err)
	} else if site == nil {
		t.Fatal("Site not found!")
	}

	actual, err := site.getBindings()
	if err != nil {
		t.Fatal(err)
	}

	if len(expected) != len(actual) {
		t.Logf("Expected %d bindings, but got %d", len(expected), len(actual))
		return false
	}

	for _, expectedBinding := range expected {
		exists := false
		if expectedBinding.IPAddress == "" {
			expectedBinding.IPAddress = "*"
		}
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
			t.Logf("Doesn't Exist: %v", expectedBinding)
			return false
		}
	}

	return true
}

// Test various bindings that could be applied to a Site
func TestSiteBinding(t *testing.T) {
	// Clean up pre-exisint IIS sites
	if err := purgeIIS(); err != nil {
		t.Fatal("Error purging: ", err)
	}

	// Create the test site in IIS
	if err := createSite(guid, "C:\\inetpub\\wwwroot", ""); err != nil {
		t.Fatal(err)
	}

	// Test http and https bindings
	bindings := []iisBinding{
		{Type: "http", Port: 8080, IPAddress: "*"},
		{Type: "https", Port: 8081, IPAddress: "*", CertHash: hash},
	}

	// Apply the bindings
	if err := applySiteBindings(guid, bindings); err != nil {
		t.Fatal(err)
	}

	// Verify that expected and actual bindings match
	if !doBindingsMatchSite(t, bindings, guid) {
		t.Fatal("Expected and Actual bindings do not match!")
	}

	// Change up bindings so that 1 is overwritten and add a new one with specific ip and hostname
	bindings = []iisBinding{
		{Type: "http", Port: 8080, IPAddress: "*"},
		{Type: "http", Port: 8081, IPAddress: ""},
		{Type: "https", Port: 8082, IPAddress: "172.17.8.101", HostName: "test.com", CertHash: hash},
	}

	// Apply the new bindings
	if err := applySiteBindings(guid, bindings); err != nil {
		t.Fatal(err)
	}

	// Verify that the new binding match actual and expected
	if !doBindingsMatchSite(t, bindings, guid) {
		t.Fatal("Expected and Actual bindings do not match!")
	}

	// Test a scenario where bindings are not supplied (which should result in no bindings applied to site)
	bindings = []iisBinding{}

	// Apply the bindings
	if err := applySiteBindings(guid, bindings); err != nil {
		t.Fatal(err)
	}

	// Verify that bindings match
	if !doBindingsMatchSite(t, bindings, guid) {
		t.Fatal("Expected and Actual bindings do not match!")
	}

	// Cleanup site
	if err := deleteSite(guid); err != nil {
		t.Fatal(err)
	}
}

// Test a basic lifecycle of a website
func TestWebsite(t *testing.T) {
	assert := assert.New(t)

	// Clean any pre-existing websites
	if err := purgeIIS(); err != nil {
		t.Fatal("Error purging: ", err)
	}

	// Basic config to be used for creating a website
	config := &TaskConfig{
		Path: "C:\\inetpub\\wwwroot",
		AppPoolIdentity: iisAppPoolIdentity{
			Identity: "SpecificUser",
			Username: "vagrant",
			Password: "vagrant",
		},
		Bindings: []iisBinding{
			{Type: "http", Port: 8080},
			{Type: "https", Port: 8081, CertHash: hash},
		},
		AppPoolResources: iisResourceLimit{
			CPULimit:    50,
			MemoryLimit: 500,
		},
		AppPoolConfigPath: "C:\\vagrant\\vagrant\\testapppool.xml",
		SiteConfigPath:    "C:\\vagrant\\vagrant\\testsite.xml",
	}

	// Create a website with the config and website name
	if err := createWebsite(guid, config); err != nil {
		t.Fatal(err)
	}

	// Ensure create website is idempotent
	if err := createWebsite(guid, config); err != nil {
		t.Fatal(err)
	}

	// Verify app pool settings match with given config
	if appPool, err := getAppPool(guid, true); err != nil {
		t.Fatal("Failed to get Site info!")
	} else {
		assert.Equal(config.AppPoolIdentity.Identity, appPool.Add.ProcessModel.IdentityType, "AppPool Identity Type doesn't match!")
		assert.Equal(config.AppPoolIdentity.Username, appPool.Add.ProcessModel.Username, "AppPool Identity Username doesn't match!")
		assert.Equal(config.AppPoolIdentity.Password, appPool.Add.ProcessModel.Password, "AppPool Identity Password doesn't match!")

		// These values are supplied by the config.xml that is imported in from vagrant/testapppool.xml and vagrant/testsite.xml
		assert.Equal("", appPool.RuntimeVersion, "AppPool RuntimeVersion doesn't match!")
		assert.Equal("Integrated", appPool.PipelineMode, "AppPool PipelineMode doesn't match!")
	}

	// Verify that site settings match the given config
	if site, err := getSite(guid, true); err != nil {
		t.Fatal("Failed to get Site info!")
	} else {
		assert.Equal(site.Site.Application.VDirs[0].PhysicalPath, config.Path, "Website path doesn't match desired path from config!")
	}

	// Start the website
	if err := startWebsite(guid); err != nil {
		t.Fatal(err)
	}

	// Ensure start website is idempotent
	if err := startWebsite(guid); err != nil {
		t.Fatal(err)
	}

	// Verify that the website is running
	if isRunning, err := isWebsiteRunning(guid); err != nil {
		t.Fatal(err)
	} else if !isRunning {
		t.Fatal("Website is not started!")
	}

	// Stop the website
	if err := stopWebsite(guid); err != nil {
		t.Fatal(err)
	}

	// Ensure stop website is idempotent
	if err := stopWebsite(guid); err != nil {
		t.Fatal(err)
	}

	// Verify that the website is not running
	if isRunning, err := isWebsiteRunning(guid); err != nil {
		t.Fatal(err)
	} else if isRunning {
		t.Fatal("Website is not stopped!")
	}

	// Delete the website
	if err := deleteWebsite(guid); err != nil {
		t.Fatal(err)
	}

	// Ensure delete website is idempotent
	if err := deleteWebsite(guid); err != nil {
		t.Fatal(err)
	}

	// Verify that the website is deleted
	if exists, err := doesWebsiteExist(guid); err != nil {
		t.Fatal(err)
	} else {
		assert.False(exists, "Website exists after deletion!")
	}
}
