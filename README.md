# Nomad IIS Driver
[![CI Actions Status](https://github.com/Roblox/nomad-driver-iis/workflows/CI/badge.svg)](https://github.com/Roblox/nomad-driver-iis/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/Roblox/nomad-driver-iis/blob/master/LICENSE)
[![Release](https://img.shields.io/badge/version-0.1.0-blue)](https://github.com/Roblox/nomad-driver-iis/releases/tag/v0.1.0)

A driver plugin for nomad to orchestrate windows IIS website tasks.

A "Website" is a combination of an application pool and a site (app, vdir, etc.).<br/>
Each allocation will create an application pool and site with the name being the allocation ID (guid).

This driver is heavily tested on Windows 2016+ and does not guarantee compatibility with older versions of Windows/IIS. IIS version and Windows versions are locked together and can be seen [here](https://en.wikipedia.org/wiki/Internet_Information_Services). Each feature/config has a minimum IIS version associated so that one can dance around them to have nomad and the IIS driver work on an older machine. The easiest way to utilize unique features for a given IIS version should be to use the application pool and site config imports provided by the task config.

---
## Configuration
### **Driver Config**

| Option | Type | Required | Default | Description |
| :---: | :---: | :---: | :---: | :--- |
| **enabled** | bool | no | true | Enable/Disable task driver. |
| **stats_interval** | string | no | 1s | Interval for collecting `TaskStats` |

### **Task Config**
| Option | Type | Required | Default | Min. IIS Version | Description |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **path** | string | yes | nil | 6.0 | Path to IIS Compatible website directory. |
| **apppool_config_path** | string | no | nil | 6.0 | Path to App Pool XML Configuration File. |
| **site_config_path** | string | no | nil | 6.0 | Path to Site XML Configuration File. |
| **apppool_identity** | string | no | ApplicationPoolIdentity | 6.0 | Application Pool Identity e.g. ('SpecificUser', 'ApplicationPoolIdentity', etc..) |
| **bindings** | block list | no | nil | 7.0 | This is needed to tie IIS Bindings to Nomad's `resources`->`network` ports to IIS as well as specify IIS Binding specific settings |
### **Bindings Block Config**
A `resource_port` OR a `port` must be provided. Due to a current limitation, we can not force at least 1 required option between multiple options. There are plans to revisit combining port options to improve UX.

| Option | Type | Required | Default | Min. IIS Version | Description |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **hostname** | string | no | nil | 7.0 | HostName attribute for a given binding. |
| **ipaddress** | string | no | * | 7.0 | IPAddress attribute for a given binding. |
| **resource_port** | string | no | nil | 7.0 | Tie a `resources`->`network` port label to the binding. This allows us to use a dynamic port given by Nomad. |
| **port** | number | no | 0 | 7.0 | Port attribute for a given binding. This will overwrite `resource_port` settings. |
| **type** | string | yes | nil | 7.0 | Type is the binding's protocol e.g. ('http', 'https', etc..) |
| **cert_hash** | string | no | nil | 7.0 | Hash of a cert that exists prior to nomad allocating an IIS website. This **must** be set for SSL bindings. |
For more info on IIS Bindings, you can go [here](https://docs.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/bindings/binding)

### **Environment Variables**
Environment variables can be set like any other Nomad task via `env` or `template` stanzas. Environment variables are only supported for IIS 10.0+.

### Meta Environment Variables
These meta env vars do not persist to the process/task. They are pulled from the env var list that is passed to the IIS application pool. These do not require a minimal IIS version as they are not used as env vars by IIS.

- `NOMAD_APPPOOL_USERNAME`
  - Sets the UserName of an application pool and will override the Application Pool Identity to `SpecificUser`
- `NOMAD_APPPOOL_PASSWORD`
  - Sets the Password of an application pool's specific user account

### Why meta env vars?
Nomad currently doesn't have a clean way to use credentials to be used by the nomad job spec itself. To get around this and not provide the user/pass credentials in plain text on the nomad job spec is to have them passed by env vars and this allows users to utilize consul/vault via the `template` stanza to promote better security. Here is the respective Nomad [issue](https://github.com/hashicorp/nomad/issues/3854).

---
## Build & Test
### **Requirements**

- [Nomad](https://www.nomadproject.io/downloads.html) >=v0.11
- [Go](https://golang.org/doc/install) >=v1.11 (to build the provider plugin)
- [Vagrant](https://www.vagrantup.com/downloads.html) >=v2.2
- [VirtualBox](https://www.virtualbox.org/) v6.0 (or any version vagrant is compatible with)

### **Building the driver**

````
$ mkdir -p $GOPATH/src/github.com/Roblox
$ cd $GOPATH/src/github.com/Roblox
$ git clone git@github.com:Roblox/nomad-driver-iis.git
$ cd nomad-driver-iis
$ make build (This will build your nomad-driver-iis executable)
````

### **Tests**
````
$ make test
````
This will run nomad-driver-iis tests in the provisioned vagrant VM.

### **Cleanup**
   ````
   make clean
   ````
   This will destroy your vagrant VM (along with all your changes) and remove the executable (win_iis.exe).

---
## Contributing

Want to fix a bug, update documentation or add a feature?<br/>
PR's are welcome!!<br/>
Test your changes locally before contributing.

The easiest way to test your changes is `make converge`.<br/>
`make converge` will:

1) Build the executable (win_iis.exe)<br/>
2) Spin up a vagrant VM (`vagrant up`) if it's not already running.<br/>
3) Provision your changes into the VM (`vagrant provision`)<br/>

Once you are in the VM:

1) nomad-driver-iis codebase (hostpath) is mounted at `C:\vagrant` in the VM.<br/>
2) Plugin (executable) is available at `C:\ProgramData\nomad\plugin`<br/>
3) Logs are available at `C:\ProgramData\nomad\logs`.<br/>
4) Tail on logs in powershell:<br/>
   ````
   $ Get-Content -path "C:\ProgramData\nomad\logs\nomad-output.log" -wait
   ````
5) Launch an example IIS website:
   ````
   $ nomad job run C:\vagrant\examples\iis-test.nomad
   ````

---
## License

Copyright 2020 Roblox Corporation

Licensed under the Apache License, Version 2.0 (the "License"). For more information read the [License](LICENSE).
