# Specify minimum Vagrant version and Vagrant API version
Vagrant.require_version ">= 1.6.0"
VAGRANTFILE_API_VERSION = "2"

# Create boxes
Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.define "nomad-dev-win" do |ncw|
    ncw.vm.hostname = "nomad-dev-win"
    ncw.vm.box = "tas50/windows_2016"
    ncw.vm.network "private_network", ip: "172.17.8.101"
    ncw.vm.provision "shell", path: "scripts/win_provision.ps1"
    ncw.vm.provider :virtualbox do |vb|
      vb.name = "nomad-dev-win"
      # The VM has a really bad time working off of 2GB of RAM, bump to 4GB
      vb.memory = 4096
    end
  end
end
