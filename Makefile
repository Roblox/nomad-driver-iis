PLUGIN_BINARY=iis-driver.exe
export GO111MODULE=on
export GOOS=windows

default: build

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf ${PLUGIN_BINARY}
	vagrant destroy -f

build:
	go build -o ${PLUGIN_BINARY} .

up:
	vagrant up

converge: build up
	vagrant provision

verify_integration:
	vagrant winrm -s cmd -c 'chdir C:\vagrant && go test ./iis/ -count=1 -v'
verify_functional:
	vagrant winrm -s cmd -c 'chdir C:\vagrant && go test tests\common.go tests\driver_test.go -count=1 -v'
verify:
	vagrant winrm -s cmd -c 'chdir C:\vagrant && go test github.com/roblox/nomad-driver-iis/tests -count=1'

test: clean converge verify
