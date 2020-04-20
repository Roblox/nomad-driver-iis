PLUGIN_BINARY=iis-driver.exe
export GO111MODULE=on
export GOOS=windows

default: build

.PHONY: clean
clean:
	rm -rf ${PLUGIN_BINARY}
	vagrant destroy -f

build:
	go build -o ${PLUGIN_BINARY} .

up:
	vagrant up

converge: build up
	  vagrant provision

test:   converge
	vagrant winrm -s cmd -c 'chdir C:\vagrant && go test ./iis/ -count=1 -v'
