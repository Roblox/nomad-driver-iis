job "iis-test" {
  datacenters = ["dc1"]
  type = "service"

  group "iis-test" {
    count = 1

    network {
      port "httplabel" {}
      port "httpslabel" {}
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

        bindings {
          type = "https"
          port = "httpslabel"
          cert_name = "WMSVC-SHA2"
        }
      }

      template {
        data = <<EOH
NOMAD_APPPOOL_USERNAME=vagrant
NOMAD_APPPOOL_PASSWORD=vagrant
EXAMPLE_ENV_VAR=test123
EOH

        destination = "secrets/file.env"
        env         = true
      }

      resources {
        cpu    = 100
        memory = 20
      }
    }
  }
}
