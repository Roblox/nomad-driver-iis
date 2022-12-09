package e2e

import (
	"io/ioutil"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvVars(t *testing.T) {
	t.Cleanup(cleanup)
	_, err := runTestJob("iis-test.nomad", "running", 30*time.Second)
	require.Nil(t, err, "failed to run job")

	// TODO: retry/await site coming up
	time.Sleep(5 * time.Second)

	resp, err := http.Get("http://localhost:81")
	require.Nil(t, err, "failed to get response from iis-test index page")

	body, err := ioutil.ReadAll(resp.Body)
	require.Nil(t, err, "failed to read response body bytes")
	assert.Regexp(t, regexp.MustCompile(`TestEnvVar:Test123!`), string(body))
}
