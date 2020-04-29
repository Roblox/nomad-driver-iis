job "iis-test" {
  datacenters = ["dc1"]
  type = "service"

  group "iis-test" {
    count = 1
    restart {
      attempts = 10
      interval = "5m"
      delay = "25s"
      mode = "delay"
    }
    task "iis-test" {
      driver = "win_iis"

      config {
        path = "C:\\inetpub\\wwwroot"
        apppool_identity {
          identity="SpecificUser"
          username="vagrant"
          password="vagrant"
        }
        bindings {
          type = "http"
          resource_port = "httplabel"
        }
      }
      resources {
        cpu    = 100
        memory = 20
        network {
          port "httplabel" {}
        }
      }
    }
  }
}
