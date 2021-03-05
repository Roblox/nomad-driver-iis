job "user-test" {
  datacenters = ["dc1"]
  type = "service"

  group "iis-test" {
    count = 1

    network {
      port "httplabel" {
        static = 81
      }
    }

    restart {
      attempts = 0
    }

    task "iis-test" {
      driver = "win_iis"

      config {
        path = "C:\\inetpub\\wwwroot"
        bindings {
          type = "http"
          port = "httplabel"
        }
      }

      template {
        destination = "secrets/file.env"
        env         = true
        data = <<EOH
NOMAD_APPPOOL_USERNAME=vagrant
NOMAD_APPPOOL_PASSWORD=vagrant
EOH
      }

      resources {
        cpu    = 100
        memory = 20
      }
    }
  }
}
