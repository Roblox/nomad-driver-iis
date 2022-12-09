package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/roblox/nomad-driver-iis/iis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJobStopCleanup(t *testing.T) {
	t.Cleanup(cleanup)
	job, err := runTestJob("iis-test.nomad", "running", 30*time.Second)
	require.Nil(t, err, "failed to run job")

	allocs, _, err := nomadClient.Jobs().Allocations(*job.ID, false, nil)
	require.Nil(t, err, "error gathering job allocs")

	require.Greater(t, len(allocs), 0)
	guid := allocs[0].ID

	time.Sleep(5 * time.Second)
	websiteExists, err := iis.DoesWebsiteExist(guid)
	require.Nil(t, err, "failed to determine website existence")
	assert.True(t, websiteExists, fmt.Sprintf("website '%s' does not exist", guid))

	_, _, err = nomadClient.Jobs().Deregister(*job.ID, false, nil)
	require.Nil(t, err, "failed to stop job")

	err = waitForJobStatus(job, "dead", 30*time.Second)
	require.Nil(t, err, err)

	time.Sleep(5 * time.Second)
	websiteExists, err = iis.DoesWebsiteExist(guid)
	require.Nil(t, err, "failed to determine website existence")
	assert.False(t, websiteExists)
}
