# Specify minimum Vagrant version and Vagrant API version
Vagrant.require_version ">= 1.6.0"
VAGRANTFILE_API_VERSION = "2"

# Provision Script for Windows Nomad
$script = <<-SCRIPT

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco install git.install -y --no-progress
choco install golang -y --no-progress
choco install nomad -y --no-progress

Stop-Service nomad
Get-CimInstance win32_service -filter "name='nomad'" | Invoke-CimMethod -Name Change -Arguments @{StartName="LocalSystem"} | Out-Null
$nomadDir = "C:\\ProgramData\\nomad"
New-Item -ItemType Directory -Path "$nomadDir\\plugin" -Force
Copy-Item "C:\\vagrant\\iis-driver.exe" -Destination "$nomadDir\\plugin" -Force
Copy-Item "C:\\vagrant\\vagrant\\win_client.hcl" -Destination "$nomadDir\\conf\\client.hcl" -Force
Start-Service nomad

Import-PfxCertificate -FilePath C:\\vagrant\\vagrant\\test.pfx -CertStoreLocation Cert:\\LocalMachine\\My -Password (ConvertTo-SecureString -String 'Test123!' -AsPlainText -Force)

Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature -IncludeManagementTools -Restart

SCRIPT

# Create boxes
Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.define "nomad-dev-win" do |ncw|
    ncw.vm.hostname = "nomad-dev-win"
    ncw.vm.box = "tas50/windows_2016"
    ncw.vm.network "private_network", ip: "172.17.8.101"
    ncw.vm.provision "shell", inline: $script
    ncw.vm.provider :virtualbox do |vb|
      vb.name = "nomad-dev-win"
      vb.memory = 2048
    end
  end
end
