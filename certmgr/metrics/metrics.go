// Package metrics defines the Prometheus metrics in use.
package metrics

import (
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof" // start a pprof endpoint
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const metricsNamespace = "certmgr"

var (
	startTime time.Time
)

func init() {
	startTime = time.Now()
}

var indexPage = `<html>
<head><title>Certificate Manager</title></head>
  <body>
    <h2>Certificate Manager</h2>
    <p>Server started at %s, listening on %s</p>
    <p><a href="https://github.com/cloudflare/certmgr/">GitHub</a></p>
    <h4>Endpoints</h4>
    <ul>
      <li>Prometheus endpoint: <a href="/metrics"><code>/metrics</code></a></li>
      <li>pprof endpoint: <a href="/debug/pprof"><code>/debug/pprof</code></a></li>
    </ul>
  </body>
</html>
`

func genServeIndex(addr string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		page := fmt.Sprintf(indexPage, startTime.Format("2006-01-02T15:04:05-0700"), addr)
		io.WriteString(w, page)
	}
}

// Start initialises the Prometheus endpoint if metrics have been
// configured.
func Start(addr, port string) {
	if addr == "" || port == "" {
		log.Warning("metrics: no prometheus address or port configured")
		return
	}

	addr = net.JoinHostPort(addr, port)
	http.HandleFunc("/", genServeIndex(addr))
	http.Handle("/metrics", promhttp.Handler())

	log.Infof("metrics: starting Prometheus endpoint on http://%s/", addr)
	go func() {
		log.Fatal(http.ListenAndServe(addr, nil))
	}()
}
