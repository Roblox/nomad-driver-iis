PLUGIN_BINARY=iis-driver.exe
export GO111MODULE=on
export GOOS=windows

default: build

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf ${PLUGIN_BINARY}

build:
	go build -o ${PLUGIN_BINARY} .
