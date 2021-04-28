Set-ExecutionPolicy Bypass -Scope Process -Force
if($env:CI -ne 'true') { Set-Location -Path 'C:\\vagrant' }
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco install git.install --version=2.25.1 -y --no-progress
choco install golang --version=1.15 -y --no-progress
choco install nomad --version=1.0.4 -y --no-progress
choco install pester --version=5.1.1 -y --no-progress

Stop-Service nomad
Get-CimInstance win32_service -filter "name='nomad'" | Invoke-CimMethod -Name Change -Arguments @{StartName="LocalSystem"} | Out-Null
$nomadDir = "C:\\ProgramData\\nomad"
New-Item -ItemType Directory -Path "$nomadDir\\plugin" -Force
Copy-Item ".\\win_iis.exe" -Destination "$nomadDir\\plugin" -Force
Copy-Item ".\\test\\win_client.hcl" -Destination "$nomadDir\\conf\\client.hcl" -Force
Start-Service nomad

Import-PfxCertificate -FilePath ".\\test\\test.pfx" -CertStoreLocation Cert:\\LocalMachine\\My -Password (ConvertTo-SecureString -String 'Test123!' -AsPlainText -Force)

Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature -IncludeManagementTools -Restart
