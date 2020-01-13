// Package metrics defines the Prometheus metrics in use.
package metrics

import (
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof" // start a pprof endpoint
	"time"

	"github.com/cloudflare/certmgr/cert"
	"github.com/cloudflare/cfssl/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// WatchCount counts the number of certificates being watched.
	WatchCount *counter

	// QueueCount counts the number of certificates actively in
	// the renewal queue.
	QueueCount *gauge

	// ExpireNext contains the time of the next certificate
	// expiry.
	ExpireNext *gauge

	// FailureCount contains a count of the number of failures to
	// generate a key pair or renew a certificate.
	FailureCount *counter

	startTime time.Time
)

func init() {
	startTime = time.Now()

	WatchCount = newCounter("cert_watching", "the number of certificates being watched by certmgr")
	QueueCount = newGauge("cert_renewal_queue", "number of certificates in the renewal queue")
	ExpireNext = newGauge("cert_next_expires", "the number of hours until the next certificate expires")
	FailureCount = newCounter("cert_renewal_failures", "the number of hours until the next certificate expires")
}

var indexPage = `<html>
<head><title>Certificate Manager</title></head>
  <body>
    <h2>Certificate Manager</h2>
    <p>Server started at %s, listening on %s</p>
    %s
    <p><a href="https://github.com/cloudflare/certmgr/">GitHub</a></p>
    <h4>Endpoints</h4>
    <ul>
      <li>Prometheus endpoint: <a href="/metrics"><code>/metrics</code></a></li>
      <li>pprof endpoint: <a href="/debug/pprof"><code>/debug/pprof</code></a></li>
    </ul>
    <h4>Current metrics:</h4>
    <ul>
      <li>Watch count: %d</li>
      <li>Certs in queue: %d</li>
      <li>Hours until the next cert expires: %d</li>
      <li>Number of times a certificate has failed to renew: %d</li>
    </ul>
    <h4>Certificates managed by this instance:</h4>
    <ul>
%s
    </ul>
  </body>
</html>
`

func genServeIndex(addr, ilink string, certs string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		page := fmt.Sprintf(indexPage, startTime.Format("2006-01-02T15:04:05-0700"),
			addr, ilink, WatchCount.Get(), int(QueueCount.Get()),
			int(ExpireNext.Get()), FailureCount.Get(), certs)
		io.WriteString(w, page)
	}
}

// Start initialises the Prometheus endpoint if metrics have been
// configured.
func Start(addr, port, ilink string, specs []*cert.Spec) {
	if addr == "" || port == "" {
		log.Warning("metrics: no prometheus address or port configured")
		return
	}

	var certs string

	for _, cert := range specs {
		var service string
		if cert.Service != "" {
			service = " for " + cert.Service
			if cert.Action != "" {
				service += " (action = " + cert.Action + ")"
			}
		}

		certs += fmt.Sprintf("      <li>%s%s</li>", cert, service)
	}

	addr = net.JoinHostPort(addr, port)
	http.HandleFunc("/", genServeIndex(addr, ilink, certs))
	http.Handle("/metrics", promhttp.Handler())

	log.Infof("metrics: starting Prometheus endpoint on http://%s/", addr)
	go func() {
		log.Fatal(http.ListenAndServe(addr, nil))
	}()
}
