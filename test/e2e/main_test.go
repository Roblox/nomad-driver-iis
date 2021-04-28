package e2e

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/nomad/api"
	nomad "github.com/hashicorp/nomad/api"
	"github.com/roblox/nomad-driver-iis/iis"
)

var (
	nomadClient *nomad.Client
	testJobDir  string
)

func TestMain(m *testing.M) {
	var err error
	nomadClient, err = initNomad()

	if err != nil {
		fmt.Println("Failed to initialize nomad client:", err)
		os.Exit(1)
	}

	// Wait for the nomad client to come online.
	// Automation may perform a restart on the client and it takes a few secs to boot
	isNomadHealthy := waitForNomadUp()
	if !isNomadHealthy {
		fmt.Println("Nomad failed to become healthy prior to tests")
		os.Exit(1)
	}

	// Get parent dir of working dir to help determine the nomad job dir
	wd, err := os.Getwd()
	if err != nil {
		fmt.Println("Failed to get e2e parent dir: ", err)
		os.Exit(1)
	}
	testJobDir = filepath.Join(filepath.Dir(wd), "jobs")

	os.Exit(m.Run())
}

func initNomad() (*nomad.Client, error) {
	conf := nomad.DefaultConfig()
	conf.Address = "http://localhost:4646"

	return nomad.NewClient(conf)
}

func waitForNomadUp() bool {
	timeout := 15 * time.Second
	endTime := time.Now().Add(timeout)
	isHealthy := false
	for {
		health, err := nomadClient.Agent().Health()
		if err == nil {
			// silently continue here as we will get errs while nomad comes back online
			isHealthy = health.Server.Ok && health.Client.Ok
		}

		if isHealthy || time.Now().After(endTime) {
			break
		}
		time.Sleep(1 * time.Second)
	}

	return isHealthy
}

func cleanup() {
	// Purge any existing Nomad jobs
	nomadJobs, _, err := nomadClient.Jobs().List(nil)
	if err != nil {
		panic(fmt.Sprintf("Error getting jobs: %v", err))
	}

	for _, nomadJob := range nomadJobs {
		nomadClient.Jobs().Deregister(nomadJob.ID, true, nil)
	}

	// Clean IIS
	if err = iis.PurgeIIS(); err != nil {
		panic(fmt.Sprintf("Error purging IIS: %v", err))
	}
	if err = iis.StartIIS(); err != nil {
		panic(fmt.Sprintf("Error starting IIS: %v", err))
	}
}

func waitForJobStatus(job *api.Job, status string, timeout time.Duration) error {
	statusMatch := false
	endTime := time.Now().Add(timeout)
	for {
		time.Sleep(1 * time.Second)

		jobInfo, _, err := nomadClient.Jobs().Info(*job.ID, nil)
		if err != nil {
			return fmt.Errorf("failed to get nomad job info: %v", err)
		}

		statusMatch = strings.EqualFold(*jobInfo.Status, status)

		if statusMatch || time.Now().After(endTime) {
			break
		}
	}
	if !statusMatch {
		return fmt.Errorf("nomad job failed to enter '%s' status in a timely manner", status)
	}

	return nil
}

func waitForAllocStatus(job *api.Job, status string, timeout time.Duration) error {
	statusMatch := false
	endTime := time.Now().Add(timeout)
	for {
		time.Sleep(1 * time.Second)

		allocs, _, err := nomadClient.Jobs().Allocations(*job.ID, false, nil)
		if err != nil {
			fmt.Errorf("error trying to gather job allocs: %v", err)
		}
		// alloc, _, err := nomadClient.Allocations().Info(allocs[0].ID, nil)
		// require.Nil(t, err, "failed to get alloc info for first allocation found")

		if len(allocs) > 0 {
			statusMatch = strings.EqualFold(allocs[0].ClientStatus, status)
		}

		if statusMatch || time.Now().After(endTime) {
			break
		}
	}
	if !statusMatch {
		return fmt.Errorf("nomad job failed to enter '%s' status in a timely manner", status)
	}

	return nil
}

func runJob(jobFilename string) (*api.Job, error) {
	// Read Job
	data, err := ioutil.ReadFile(filepath.Join(testJobDir, jobFilename))
	if err != nil {
		return nil, fmt.Errorf("error trying to read nomad job spec: %v", err)
	}

	// Parse Job
	job, err := nomadClient.Jobs().ParseHCL(string(data), false)
	if err != nil {
		return job, fmt.Errorf("error trying to parse nomad job spec: %v", err)
	}

	// Create test job
	_, _, err = nomadClient.Jobs().Register(job, nil)
	if err != nil {
		return job, fmt.Errorf("error trying to register job: %v", err)
	}
	return job, err
}

func runTestJobWithAllocStatus(jobFilename string, desiredStatus string, duration time.Duration) (*api.Job, error) {
	job, err := runJob(jobFilename)
	if err != nil {
		return job, err
	}

	// Wait for job to enter running status
	err = waitForAllocStatus(job, desiredStatus, duration)

	return job, err
}

func runTestJob(jobFilename string, desiredStatus string, duration time.Duration) (*api.Job, error) {
	job, err := runJob(jobFilename)
	if err != nil {
		return job, err
	}

	// Wait for job to enter running status
	err = waitForJobStatus(job, desiredStatus, duration)

	return job, err
}
