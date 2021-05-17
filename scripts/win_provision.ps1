Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco install git.install --version=2.25.1 -y --no-progress
choco install golang --version=1.14 -y --no-progress
choco install nomad --version=0.11.0 -y --no-progress
choco install consul --version=1.8.5 -y --no-progress

Stop-Service nomad
Stop-Service consul

Get-CimInstance win32_service -filter "name='consul'" | Invoke-CimMethod -Name Change -Arguments @{StartName="LocalSystem"} | Out-Null
$consulDir = "C:\\ProgramData\\consul"
New-Item -ItemType Directory -Path "$consulDir\\data" -Force
Copy-Item "C:\\vagrant\\vagrant\\consul.json" -Destination "$consulDir\\config\\consul.json" -Force
Start-Service consul

Get-CimInstance win32_service -filter "name='nomad'" | Invoke-CimMethod -Name Change -Arguments @{StartName="LocalSystem"} | Out-Null
$nomadDir = "C:\\ProgramData\\nomad"
New-Item -ItemType Directory -Path "$nomadDir\\plugin" -Force
Copy-Item "C:\\vagrant\\win_iis.exe" -Destination "$nomadDir\\plugin" -Force
Copy-Item "C:\\vagrant\\vagrant\\win_client.hcl" -Destination "$nomadDir\\conf\\client.hcl" -Force
Start-Service nomad

Import-PfxCertificate -FilePath C:\\vagrant\\vagrant\\test.pfx -CertStoreLocation Cert:\\LocalMachine\\My -Password (ConvertTo-SecureString -String 'Test123!' -AsPlainText -Force)

Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature -IncludeManagementTools -Restart
