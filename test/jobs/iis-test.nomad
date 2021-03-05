job "iis-test" {
  datacenters = ["dc1"]
  type = "service"

  group "iis-test" {
    count = 1

    network {
      port "httplabel" {
        static = 81
      }
      port "httpslabel" {}
    }

    restart {
      attempts = 0
    }

    task "iis-test" {
      driver = "win_iis"

      config {
        path = "local/website"
        bindings {
          type = "http"
          port = "httplabel"
        }
        bindings {
          type = "https"
          port = "httpslabel"
          cert_hash = "854d57551e79656159a0081054fbc08c6c648f86"
        }
      }


      template {
        data = <<EOH
TEST_WIN_IIS=Test123!
EOH

        destination = "secrets/file.env"
        env         = true
      }

      resources {
        cpu    = 100
        memory = 20
      }

      template {
        destination = "local/website/default.aspx"
        data = <<EOH
<%@ Page Language="C#"%>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <body runat="server">
    TestEnvVar:<%=System.Environment.GetEnvironmentVariable("TEST_WIN_IIS") %>
  </body>
</html>
EOH
      }

      template {
        destination = "local/website/cpu.aspx"
        data = <<EOH
<%@ Page Language="C#"%>
<html xmlns="http://www.w3.org/1999/xhtml" >
    <head runat="server">
        <title>Untitled Page</title>
    </head>
    <body>
        <div>
        <%var input = Request.QueryString["cpu"];
        if (input == null)
        {
            input = "50";
        }

        int percentage;
        if (!int.TryParse(input, out percentage) || percentage < 0 || percentage > 100)
            throw new ArgumentException("percentage");

        var watch = new System.Diagnostics.Stopwatch();
        watch.Start();
        while (true)
        {
            // Make the loop go on for "percentage" milliseconds then sleep the
            // remaining percentage milliseconds. So 40% utilization means work 40ms and sleep 60ms
            if (watch.ElapsedMilliseconds > percentage)
            {
                System.Threading.Thread.Sleep(100 - percentage);
                watch.Reset();
                watch.Start();
            }
        }
        %>
        </div>
    </body>
</html>

<configuration>
  <system.web>
    <httpRuntime executionTimeout="30" />
  </system.web>
</configuration>
EOH
      }
    }
  }
}
