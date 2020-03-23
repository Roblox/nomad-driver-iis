job "iis-job" {
  datacenters = ["dc1"]
  type        = "service"

  group "iis-group" {
    task "iis-task" {
      driver = "win_iis"

      config {
        greeting = "iis"
      }
    }
  }
}
