package main

import (
	log "github.com/hashicorp/go-hclog"

	// TODO: update the path below to match your own repository
	"github.com/hashicorp/nomad-skeleton-driver-plugin/hello"

	"github.com/hashicorp/nomad/plugins"
)

func main() {
	// Serve the plugin
	plugins.Serve(factory)
}

// factory returns a new instance of a nomad driver plugin
func factory(log log.Logger) interface{} {
	return hello.NewPlugin(log)
}
