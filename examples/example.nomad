job "iis-job" {
  datacenters = ["dc1"]
  type        = "service"

  group "iis-group" {
    task "iis-task" {
      driver = "nomad-driver-iis"

      config {
        greeting = "iis"
      }
    }
  }
}
