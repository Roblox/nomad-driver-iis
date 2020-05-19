Nomad IIS Driver
==========

A driver plugin for nomad to orchestrate windows IIS website tasks.

A "Website" is a combination of an application pool and a site (app, vdir, etc.).<br/>
Each allocation will create an application pool and site with the name being the allocation ID (guid).

Requirements
-------------------

- [Nomad](https://www.nomadproject.io/downloads.html) >=v0.11
- [Go](https://golang.org/doc/install) >=v1.11 (to build the provider plugin)
- [Vagrant](https://www.vagrantup.com/downloads.html) >=v2.2
- [VirtualBox](https://www.virtualbox.org/) v6.0 (or any version vagrant is compatible with)

Building the driver
-------------------

````
$ mkdir -p $GOPATH/src/github.com/Roblox
$ cd $GOPATH/src/github.com/Roblox
$ git clone git@github.com:Roblox/nomad-driver-iis.git
$ cd nomad-driver-iis
$ make build (This will build your nomad-driver-iis executable)
````

Tests
------------------
````
$ make test
````
This will run nomad-driver-iis tests in the provisioned vagrant VM.

Contributing to nomad-iis-driver
------------------
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

Cleanup
-------------------
````
make clean
````
This will destroy your vagrant VM (along with all your changes) and remove the executable (win_iis.exe).

License
-------------------

Copyright 2020 Roblox Corporation

Licensed under the Apache License, Version 2.0 (the "License"). For more information read the [License](LICENSE).
