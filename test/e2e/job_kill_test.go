package e2e

import (
	"testing"
	"time"

	"github.com/roblox/nomad-driver-iis/iis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJobStatusKillSite(t *testing.T) {
	t.Cleanup(cleanup)
	job, err := runTestJob("iis-test.nomad", "running", 30*time.Second)
	require.Nil(t, err, "failed to run job")

	allocs, _, err := nomadClient.Jobs().Allocations(*job.ID, false, nil)
	require.Nil(t, err, "error gathering job allocs")

	assert.Greater(t, len(allocs), 0)
	guid := allocs[0].ID

	time.Sleep(5 * time.Second)
	err = iis.StopWebsite(guid)
	require.Nil(t, err, "failed to stop website")

	err = waitForAllocStatus(job, "failed", 30*time.Second)
	require.Nil(t, err, "alloc did not fail after website stopped")
}
