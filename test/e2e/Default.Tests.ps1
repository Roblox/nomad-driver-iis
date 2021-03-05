Describe "PreReqs" {
  It "Nomad Installed" {
    $cmd = Get-Command "nomad.exe" -ErrorAction SilentlyContinue
    $cmd | Should -Not -BeNullOrEmpty -ErrorAction Stop
  }

  It "Nomad Driver Installed" {
    $driverFile = Get-Item "C:\ProgramData\nomad\plugin\win_iis.exe" -ErrorAction SilentlyContinue
    $driverFile | Should -Not -BeNullOrEmpty
  }

  It "IIS Installed" {
    $state = (Get-WindowsFeature Web-Server).InstallState
    $state | Should -Be "Installed"
  }

  It "Nomad Running" {
    $service = Get-Service "nomad"
    $service | Should -Not -BeNullOrEmpty
    $service.Status | Should -Be "Running"
  }
}

Describe "TestE2E" {
  BeforeAll {
    Import-Module WebAdministration
  }
  BeforeEach {
    # Clean Nomad Jobs
    $jobsContent = Invoke-RestMethod -Uri "http://localhost:4646/v1/jobs" -Method GET
    if ($jobsContent) {
      $jobsContent | ForEach-Object {
        $url = "http://localhost:4646/v1/job/" + $_.ID + '?purge=true';
        #$bodyParams = @{purge=$true} | ConvertTo-Json;
        Invoke-RestMethod -Uri $url -Method DELETE };
    }
    # # Wait for all jobs to stop
    # $timeout = New-TimeSpan -Seconds 15
    # $endTime = (Get-Date).Add($timeout)
    # $allStopped = $false
    # # Nomad System GC will not release jobs in these statuses
    # $runningStatuses = @('pending', 'running')
    # do {
    #   $allStopped = $true
    #   $jobsContent = Invoke-RestMethod -Uri "http://localhost:4646/v1/jobs" -Method GET
    #   Write-Host $jobsContent
    #   if ($jobsContent) {
    #     foreach ($job in $jobsContent) {
    #       Write-Host $job
    #       if ($runningStatuses.Contains($job.Status.ToLower())) { $allStopped = $false }
    #     }
    #   }
    #   Write-Host $allStopped
    # }
    # until ($allStopped -or ((Get-Date) -gt $endTime))
    # $allStopped | Should -Be $true
    # # Perform Nomad GC to clear all jobs from existence
    # # Nomad isn't keen to destroying jobs immediately after they are stopped
    # Start-Sleep -s 10
    & "nomad.exe" "system" "gc"

    # Clean IIS
    Start-Service "w3svc"
    #Get-Process "w3wp" -ErrorAction SilentlyContinue | Stop-Process -Confirm:$false
    Get-Website | Remove-Website -ErrorAction SilentlyContinue
    Get-IISAppPool | Remove-WebAppPool -ErrorAction SilentlyContinue
    Reset-IISServerManager -Confirm:$false
  }

  It "Verify Nomad and Websites Are Empty" {
    $jobsContent = Invoke-RestMethod -Uri "http://localhost:4646/v1/jobs" -Method GET
    $jobsContent | Should -BeNullOrEmpty

    Get-Website | Should -BeNullOrEmpty
    Get-IISAppPool | Should -BeNullOrEmpty
  }

  It "Test Fingerprinting" {
    # Waiting for health of the driver to become "True" before starting tests
    # All fingerprinting state changing in nomad takes about 45s to fullfill
    $timeout = New-TimeSpan -Seconds 45
    $endTime = (Get-Date).Add($timeout)
    do {
        $result = (& "nomad.exe" "node" "status" "-json" | Out-String | ConvertFrom-Json)[0].Drivers.win_iis.Healthy
    }
    until ($result -eq $true -or ((Get-Date) -gt $endTime))
    $result | Should -Be $true

    $driver = (& "nomad.exe" "node" "status" "-json" | Out-String | ConvertFrom-Json)[0].Drivers.win_iis

    $driver.Attributes | Select-Object -ExpandProperty "driver.win_iis.version" | Should -Match "^[0-9]*\.[0-9]*\.[0-9]*$"
    $driver.Attributes | Select-Object -ExpandProperty "driver.win_iis.iis_version" | Should -Match "^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$"

    # Stopping IIS
    Stop-Service "w3svc"

    # Waiting for health of the driver to become "False"
    $endTime = (Get-Date).Add($timeout)
    do {
        $result = (& "nomad.exe" "node" "status" "-json" | Out-String | ConvertFrom-Json)[0].Drivers.win_iis.Healthy
    }
    until ($result -eq $false -or ((Get-Date) -gt $endTime))
    $result | Should -Be $false

    # Stopping IIS
    Start-Service "w3svc"

    # Waiting for health of the driver to become "False"
    $endTime = (Get-Date).Add($timeout)
    do {
        $result = (& "nomad.exe" "node" "status" "-json" | Out-String | ConvertFrom-Json)[0].Drivers.win_iis.Healthy
    }
    until ($result -eq $true -or ((Get-Date) -gt $endTime))
    $result | Should -Be $true
  }

  It "Nomad Job Kill Site" {
    & "nomad.exe" "job" "run" "C:\vagrant\examples\iis-test.nomad"

    $job = $null
    # Wait for the job to be placed
    $timeout = New-TimeSpan -Seconds 30
    $endTime = (Get-Date).Add($timeout)
    $isRunning = $false
    do {
      $job = Invoke-RestMethod -Uri "http://localhost:4646/v1/job/iis-test" -Method GET
      if ($job -and $job.Status.ToLower() -eq 'running') {
        $isRunning = $true
      }
    }
    until ($isRunning -or ((Get-Date) -gt $endTime))
    $isRunning | Should -Be $true

    $allocs = Invoke-RestMethod -Uri "http://localhost:4646/v1/job/iis-test/allocations" -Method GET
    $allocs | Should -Not -BeNullOrEmpty

    $guid = $allocs[-1].ID

    Reset-IISServerManager -Confirm:$false
    $site = Get-IISSite $guid
    $appPool = Get-IISAppPool $guid

    $site | Should -Not -BeNullOrEmpty
    $appPool | Should -Not -BeNullOrEmpty

    Stop-IISSite $guid -Confirm:$false

    # Wait for the job to stop running
    $endTime = (Get-Date).Add($timeout)
    do {
      $job = Invoke-RestMethod -Uri "http://localhost:4646/v1/job/iis-test" -Method GET
      if ($job -and $job.Status.ToLower() -ne 'running') {
        $isRunning = $false
      }
    }
    until (!$isRunning -or ((Get-Date) -gt $endTime))
    $isRunning | Should -Be $false
  }

  It "Nomad Job Kill App Pool" {
    & "nomad.exe" "job" "run" "C:\vagrant\examples\iis-test.nomad"
    # Wait for the job to start running
    $timeout = New-TimeSpan -Seconds 30
    $endTime = (Get-Date).Add($timeout)
    $isRunning = $false
    do {
      $job = Invoke-RestMethod -Uri "http://localhost:4646/v1/job/iis-test" -Method GET
      if ($job -and $job.Status.ToLower() -eq 'running') {
        $isRunning = $true
      }
    }
    until ($isRunning -or ((Get-Date) -gt $endTime))
    $isRunning | Should -Be $true
  }

  It "Nomad Stop Job" {
    & "nomad.exe" "job" "run" "$PSScriptRoot\..\jobs\iis-test.nomad"

    $job = $null
    # Wait for the job to be placed
    $timeout = New-TimeSpan -Seconds 45
    $endTime = (Get-Date).Add($timeout)
    $isRunning = $false
    do {
      $job = Invoke-RestMethod -Uri "http://localhost:4646/v1/job/iis-test" -Method GET
      if ($job -and $job.Status.ToLower() -eq 'running') {
        $isRunning = $true
      }
    }
    until ($isRunning -or ((Get-Date) -gt $endTime))
    $isRunning | Should -Be $true

    $allocs = Invoke-RestMethod -Uri "http://localhost:4646/v1/job/iis-test/allocations" -Method GET
    $allocs | Should -Not -BeNullOrEmpty

    $guid = $allocs[0].ID

    Reset-IISServerManager -Confirm:$false
    $site = Get-IISSite $guid
    $appPool = Get-IISAppPool $guid

    $site | Should -Not -BeNullOrEmpty
    $appPool | Should -Not -BeNullOrEmpty

    & "nomad.exe" "job" "stop" "iis-test"

    # Wait for the job to stop running
    $endTime = (Get-Date).Add($timeout)
    do {
      Reset-IISServerManager -Confirm:$false
      $site = Get-IISSite $guid
      $appPool = Get-IISAppPool $guid
    }
    until ((!$site -and !$appPool) -or ((Get-Date) -gt $endTime))
    $site | Should -BeNullOrEmpty
    $appPool | Should -BeNullOrEmpty
  }

  It "Nomad Job Identity and Stats" {
    & "nomad.exe" "job" "run" "$PSScriptRoot\..\jobs\iis-test.nomad"

    $job = $null
    # Wait for the job to be placed
    $timeout = New-TimeSpan -Seconds 45
    $endTime = (Get-Date).Add($timeout)
    $isRunning = $false
    do {
      $job = Invoke-RestMethod -Uri "http://localhost:4646/v1/job/iis-test" -Method GET
      if ($job -and $job.Status.ToLower() -eq 'running') {
        $isRunning = $true
      }
    }
    until ($isRunning -or ((Get-Date) -gt $endTime))
    $isRunning | Should -Be $true

    $allocs = Invoke-RestMethod -Uri "http://localhost:4646/v1/job/iis-test/allocations" -Method GET
    $allocs | Should -Not -BeNullOrEmpty

    $guid = $allocs[0].ID

    Get-Item "IIS:\AppPools\$guid" | Select-Object -ExpandProperty processModel | Select-Object -expand identityType | Should -Be 'ApplicationPoolIdentity'

    # Call cpu.aspx to trigger higher cpu and mem usage
    # Don't wait for the result, we only care about stat collection
    Start-Job -ScriptBlock { Invoke-RestMethod -Uri "http://localhost:81/cpu.aspx" -Method GET }

    $timeout = New-TimeSpan -Seconds 45
    $endTime = (Get-Date).Add($timeout)
    $cpuPercent = 0
    $memRSS = 0
    # Stat Collecting takes 5s
    Start-Sleep -s 5
    do {
      $allocStats = Invoke-RestMethod -Uri "http://localhost:4646/v1/client/allocation/$guid/stats" -Method GET
      if ($allocStats) {
        $cpuPercent = $allocStats.ResourceUsage.CpuStats.Percent
        $memRSS = $allocStats.ResourceUsage.MemoryStats.RSS
      }
    }
    until (($cpuPercent -gt 0 -and $memRSS -gt 0) -or ((Get-Date) -gt $endTime))
    $cpuPercent | Should -BeGreaterThan 0
    $memRSS | Should -BeGreaterThan 0
  }

  It "Nomad Env Var" {
    & "nomad.exe" "job" "run" "$PSScriptRoot\..\jobs\iis-test.nomad"

    $job = $null
    # Wait for the job to be placed
    $timeout = New-TimeSpan -Seconds 45
    $endTime = (Get-Date).Add($timeout)
    $isRunning = $false
    do {
      $job = Invoke-RestMethod -Uri "http://localhost:4646/v1/job/iis-test" -Method GET
      if ($job -and $job.Status.ToLower() -eq 'running') {
        $isRunning = $true
      }
    }
    until ($isRunning -or ((Get-Date) -gt $endTime))
    $isRunning | Should -Be $true

    (Invoke-RestMethod -Uri "http://localhost:81" -Method GET).html.body | Should -Match "TestEnvVar:Test123!"
  }

  It "Placement Fail: Bindings" {
    & "nomad.exe" "job" "run" "$PSScriptRoot\..\jobs\bad-binding.nomad"

    $job = $null
    # Wait for the job to be placed
    $timeout = New-TimeSpan -Seconds 45
    $endTime = (Get-Date).Add($timeout)
    $isFailed = $false
    do {
      $allocs = Invoke-RestMethod -Uri "http://localhost:4646/v1/allocations" -Method GET
      if ($allocs -and $allocs[-1].ClientStatus.ToLower() -eq 'failed') {
        $isFailed = $true
      }
    }
    until ($isFailed -or ((Get-Date) -gt $endTime))
    $isFailed | Should -Be $true
  }

  It "Placement Fail: Cert" {
    & "nomad.exe" "job" "run" "$PSScriptRoot\..\jobs\bad-cert.nomad"

    $job = $null
    # Wait for the job to be placed
    $timeout = New-TimeSpan -Seconds 30
    $endTime = (Get-Date).Add($timeout)
    $isFailed = $false
    do {
      $allocs = Invoke-RestMethod -Uri "http://localhost:4646/v1/allocations" -Method GET
      if ($allocs -and $allocs[-1].ClientStatus.ToLower() -eq 'failed') {
        $isFailed = $true
      }
    }
    until ($isFailed -or ((Get-Date) -gt $endTime))
    $isFailed | Should -Be $true
  }

  It "User Test" {
    & "nomad.exe" "job" "run" "$PSScriptRoot\..\jobs\user-test.nomad"

    $job = $null
    # Wait for the job to be placed
    $timeout = New-TimeSpan -Seconds 45
    $endTime = (Get-Date).Add($timeout)
    $isRunning = $false
    do {
      $allocs = Invoke-RestMethod -Uri "http://localhost:4646/v1/allocations" -Method GET
      if ($allocs -and $allocs[-1].ClientStatus.ToLower() -eq 'running') {
        $isRunning = $true
      }
    }
    until ($isRunning -or ((Get-Date) -gt $endTime))
    $isRunning | Should -Be $true

    $allocs = Invoke-RestMethod -Uri "http://localhost:4646/v1/job/user-test/allocations" -Method GET
    $allocs | Should -Not -BeNullOrEmpty

    $guid = $allocs[-1].ID

    Get-Item "IIS:\AppPools\$guid" | Select-Object -ExpandProperty processModel | Select-Object -expand identityType | Should -Be 'SpecificUser'
  }
}
