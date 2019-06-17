// Package metrics defines the Prometheus metrics in use.
package metrics

import (
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof" // start a pprof endpoint
	"time"

	"github.com/cloudflare/cfssl/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const metricsNamespace = "certmgr"

var (
	startTime time.Time

	// SpecWatchCount counts the number of specs being watched.
	SpecWatchCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "specs_watched_total",
			Help:      "Number of specs being watched",
		},
		[]string{"spec_path", "svcmgr", "action", "ca"},
	)

	// Expires contains the time of the next certificate
	// expiry.
	Expires = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "cert_expire_timestamp",
			Help:      "The unix time for when the given spec and type expires",
		},
		[]string{"spec_path", "type"},
	)

	// FailureCount contains a count of the number of failures to
	// generate a key pair or renew a certificate.
	FailureCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "cert_renewal_failures",
			Help:      "Number of keypair generation or cert renewal failures",
		},
		[]string{"spec_path"},
	)

	// AlgorithmMismatchCount counts mismatches occurred between algorithm on disk vs algorithm in spec
	AlgorithmMismatchCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "algorithm_mismatch",
			Help:      "Number of mismatches between cert algorithm on disk vs algorithm specified in spec",
		},
		[]string{"spec_path"},
	)

	// KeysizeMismatchCount counts mismatches occurred between keysize on disk vs keysize in spec
	KeysizeMismatchCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "keysize_mismatch",
			Help:      "Number of mismatches between keysize disk vs keysize specified in spec",
		},
		[]string{"spec_path"},
	)

	// HostnameMismatchCount counts mismatches occurred between cert hostnames on disk vs cert hostnames in spec
	HostnameMismatchCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "hostname_mismatch",
			Help:      "Number of mismatches between cert hostnames on disk vs cert hostnames specified in spec",
		},
		[]string{"spec_path"},
	)

	// KeypairMismatchCount counts TLS mismatch between key and certificate on disk
	KeypairMismatchCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "keypair_mismatch",
			Help:      "Number of TLS mismatches between key and certificate on disk",
		},
		[]string{"spec_path"},
	)

	// ManagerInterval is set to the interval at which a cert manager wakes up and does its checks
	ManagerInterval = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "manager_interval_seconds",
			Help:      "the time interval that manager wakes up and does checks",
		},
		[]string{"directory"},
	)

	// ActionCount counts actions taken by spec
	ActionCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "action_count",
			Help:      "Number of times a spec has taken action",
		},
		[]string{"spec_path", "change_type"},
	)

	// ActionFailure counts number of times an action taken by spec failed
	ActionFailure = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "action_failure",
			Help:      "Number of times a spec's action has failed",
		},
		[]string{"spec_path", "change_type"},
	)
)

func init() {
	startTime = time.Now()

	prometheus.MustRegister(SpecWatchCount)
	prometheus.MustRegister(Expires)
	prometheus.MustRegister(FailureCount)
	prometheus.MustRegister(AlgorithmMismatchCount)
	prometheus.MustRegister(KeysizeMismatchCount)
	prometheus.MustRegister(HostnameMismatchCount)
	prometheus.MustRegister(KeypairMismatchCount)
	prometheus.MustRegister(ManagerInterval)
	prometheus.MustRegister(ActionCount)
	prometheus.MustRegister(ActionFailure)
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
