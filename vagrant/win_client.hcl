# Increase log verbosity
log_level = "INFO"

# Setup data dir
data_dir = "C:\\ProgramData\\nomad\\data"
plugin_dir = "C:\\ProgramData\\nomad\\plugin"

consul {
  address = "localhost:8500"
}

# Enable server mode
server {
  enabled = true
  bootstrap_expect = 1
}

# Enable client mode
client {
    enabled = true
}

advertise {
    http = "172.17.8.101"
    rpc = "172.17.8.101"
    serf = "172.17.8.101"
}

plugin "win_iis" {
  config {
    enabled = true
    stats_interval = "5s"
  }
}
