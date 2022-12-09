package e2e

import (
	"testing"
	"time"

	"github.com/roblox/nomad-driver-iis/iis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIISUser(t *testing.T) {
	t.Cleanup(cleanup)
	job, err := runTestJob("user-test.nomad", "running", 30*time.Second)
	require.Nil(t, err, "failed to run job")

	// TODO: retry/await site coming up
	time.Sleep(5 * time.Second)

	allocs, _, err := nomadClient.Jobs().Allocations(*job.ID, false, nil)
	if err != nil {
		t.Fatal("Error trying to job allocs:", err)
	}

	assert.Greater(t, len(allocs), 0)
	guid := allocs[0].ID

	appPool, err := iis.GetAppPool(guid, true)
	require.Nil(t, err, "failed to get apppool info")
	assert.Equal(t, "SpecificUser", appPool.Add.ProcessModel.IdentityType, "AppPool Identity Type doesn't match!")
}
