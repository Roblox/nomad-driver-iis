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

      artifact {
        source = "https://github.com/iamabhishek-dubey/nomad-driver-iis/releases/download/v0.4/test-hello-world.zip"
        options {
          archive = true
        }
      }
      config {
        path = "${NOMAD_TASKS_DIR}\\netcoreapp2.1"

        apppool_identity {
          identity = "NetworkService"
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
      service {
        name = "iis-test"
        tags = ["iis-test", "windows-iis-test"]
        port = "httplabel"
        check {
          type = "tcp"
          interval = "10s"
          timeout = "2s"
        }
      }
    }
  }
}
