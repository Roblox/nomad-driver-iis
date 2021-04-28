PLUGIN_BINARY=win_iis.exe
export GO111MODULE=on
export GOOS=windows

ifeq ($(OS),Windows_NT)
	RMCMD = del /f 
else
	RMCMD = rm -f
endif

default: build

.PHONY: clean test
clean:
	${RMCMD} ${PLUGIN_BINARY}
	vagrant destroy -f

build:
	go build -o ${PLUGIN_BINARY} .

up:
	vagrant up

converge: build up
	  vagrant provision

test: converge
	vagrant winrm -s cmd -c 'chdir C:\vagrant && go test ./iis/ -count=1 -v'
	vagrant winrm -s cmd -c 'chdir C:\vagrant && go test ./test/e2e -count=1 -v'

