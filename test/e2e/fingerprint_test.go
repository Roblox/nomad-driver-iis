package e2e

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	nomad "github.com/hashicorp/nomad/api"
	"github.com/roblox/nomad-driver-iis/iis"
	"github.com/stretchr/testify/assert"
)

func getNomadNode() (*nomad.NodeListStub, error) {
	nodes, _, err := nomadClient.Nodes().List(nil)
	if err != nil {
		return nil, fmt.Errorf("Error getting NomadNode: %v", err)
	}

	return nodes[0], nil
}

func TestFingerprintKeys(t *testing.T) {
	if err := iis.StopIIS(); err != nil {
		t.Fatal("Error trying to stop IIS!")
	}

	node, err := getNomadNode()
	if err != nil {
		t.Fatal(err)
	}

	assert.Regexp(t, regexp.MustCompile(`^[0-9]*\.[0-9]*\.[0-9]*$`), node.Drivers["win_iis"].Attributes["driver.win_iis.version"])
	assert.Regexp(t, regexp.MustCompile(`^[0-9]*\.[0-9]*\.[0-9]*\.[[0-9]*$`), node.Drivers["win_iis"].Attributes["driver.win_iis.iis_version"])
}

func TestFingerprintHealth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	t.Cleanup(cleanup)

	if err := iis.StopIIS(); err != nil {
		t.Fatal("Error trying to stop IIS!")
	}

	timeout := 45 * time.Second
	node, err := getNomadNode()
	if err != nil {
		t.Fatal(err)
	}

	endTime := time.Now().Add(timeout)
	isHealthy := true
	for {
		nodeInfo, _, err := nomadClient.Nodes().Info(node.ID, nil)
		if err != nil {
			t.Fatal("Failed to get nomad node ", err)
		}

		isHealthy = nodeInfo.Drivers["win_iis"].Healthy

		if !isHealthy || time.Now().After(endTime) {
			break
		}
		time.Sleep(1 * time.Second)
	}
	assert.False(t, isHealthy)

	// Turn IIS back on and wait for health state to change
	if err := iis.StartIIS(); err != nil {
		t.Fatal("Error trying to start IIS!")
	}
	endTime = time.Now().Add(timeout)
	isHealthy = false
	for {
		nodeInfo, _, err := nomadClient.Nodes().Info(node.ID, nil)
		if err != nil {
			t.Fatal("Failed to get nomad node ", err)
		}

		isHealthy = nodeInfo.Drivers["win_iis"].Healthy

		if isHealthy || time.Now().After(endTime) {
			break
		}
		time.Sleep(1 * time.Second)
	}
	assert.True(t, isHealthy)
}
