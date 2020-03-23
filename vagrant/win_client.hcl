# Increase log verbosity
log_level = "INFO"

# Setup data dir
data_dir = "C:\\ProgramData\\nomad\\data"
plugin_dir = "C:\\ProgramData\\nomad\\plugin"

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

plugin "raw_exec" {
  config {
    enabled = true
  }
}

plugin "win_iis" {
  config {
    enabled = true
  }
}
