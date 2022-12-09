package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJobStats(t *testing.T) {
	t.Cleanup(cleanup)
	job, err := runTestJob("iis-test.nomad", "running", 30*time.Second)
	require.Nil(t, err, "failed to run job")

	// TODO: retry/await site coming up
	time.Sleep(5 * time.Second)

	// fire and forget
	// there ought to be a cleaner way to handle this, will have to ask during PR
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	req, err := http.NewRequest("GET", "http://localhost:81/cpu.aspx", nil)
	require.Nil(t, err, "failed to make a request to cpu test page")
	client.Do(req)

	allocs, _, err := nomadClient.Jobs().Allocations(*job.ID, false, nil)
	require.Nil(t, err, "failed to get allocations for job")
	alloc, _, err := nomadClient.Allocations().Info(allocs[0].ID, nil)
	require.Nil(t, err, "failed to get alloc info for first allocation found")
	stats, err := nomadClient.Allocations().Stats(alloc, nil)
	require.Nil(t, err, "failed to get stats for allocation")

	assert.Greater(t, stats.ResourceUsage.CpuStats.Percent, float64(0))
	assert.Greater(t, stats.ResourceUsage.MemoryStats.RSS, uint64(0))
}
