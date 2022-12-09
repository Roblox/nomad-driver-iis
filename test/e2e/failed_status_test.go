package e2e

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBadCert(t *testing.T) {
	t.Cleanup(cleanup)
	_, err := runTestJobWithAllocStatus("bad-cert.nomad", "failed", 30*time.Second)
	require.Nil(t, err, "failed to run job")
}

func TestBadBindings(t *testing.T) {
	t.Cleanup(cleanup)
	_, err := runTestJobWithAllocStatus("bad-binding.nomad", "failed", 30*time.Second)
	require.Nil(t, err, "failed to run job")
}
