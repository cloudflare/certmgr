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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	startTime time.Time

	// WatchCount counts the number of certificates being watched.
	WatchCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cert_watching",
			Help: "Number of certs being watched",
		},
		[]string{"spec_path", "svcmgr", "cert_action", "cert_age", "ca", "ca_age"},
	)

	// QueueCount counts the number of certificates actively in
	// the renewal queue.
	QueueCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cert_renewal_queue",
			Help: "number of certificates in the renewal queue",
		},
		[]string{"spec_path"},
	)

	// ExpireNext contains the time of the next certificate
	// expiry.
	ExpireNext = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cert_next_expires",
			Help: "the number of hours until the next certificate expires",
		},
		[]string{"spec_path"},
	)

	// FailureCount contains a count of the number of failures to
	// generate a key pair or renew a certificate.
	FailureCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cert_renewal_failures",
			Help: "Number of keypair generation or cert renewal failures",
		},
		[]string{"spec_path"},
	)

	// AlgorithmMismatchCount counts mismatches occurred between algorithm on disk vs algorithm in spec
	AlgorithmMismatchCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "algorithm_mismatch",
			Help: "Number of mismatches between cert algorithm on disk vs algorithm specified in spec",
		},
		[]string{"spec_path"},
	)

	// KeysizeMismatchCount counts mismatches occurred between keysize on disk vs keysize in spec
	KeysizeMismatchCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keysize_mismatch",
			Help: "Number of mismatches between keysize disk vs keysize specified in spec",
		},
		[]string{"spec_path"},
	)

	// HostnameMismatchCount counts mismatches occurred between cert hostnames on disk vs cert hostnames in spec
	HostnameMismatchCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "hostname_mismatch",
			Help: "Number of mismatches between cert hostnames on disk vs cert hostnames specified in spec",
		},
		[]string{"spec_path"},
	)

	// KeypairMismatchCount counts TLS mismatch between key and certificate on disk
	KeypairMismatchCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keypair_mismatch",
			Help: "Number of TLS mismatches between key and certificate on disk",
		},
		[]string{"spec_path"},
	)

	// ManagerInterval is set to the interval at which a cert manager wakes up and does its checks
	ManagerInterval = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "manager_interval",
			Help: "the time interval that manager wakes up and does checks",
		},
		[]string{"directory", "interval"},
	)

	// ActionCount counts actions taken by spec
	ActionCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "action_count",
			Help: "Number of times a spec has taken action",
		},
		[]string{"spec_path", "change_type"},
	)
)

func init() {
	startTime = time.Now()

	prometheus.MustRegister(WatchCount)
	prometheus.MustRegister(QueueCount)
	prometheus.MustRegister(ExpireNext)
	prometheus.MustRegister(FailureCount)
	prometheus.MustRegister(AlgorithmMismatchCount)
	prometheus.MustRegister(KeysizeMismatchCount)
	prometheus.MustRegister(HostnameMismatchCount)
	prometheus.MustRegister(KeypairMismatchCount)
	prometheus.MustRegister(ManagerInterval)
	prometheus.MustRegister(ActionCount)
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
			addr, ilink, certs)
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
