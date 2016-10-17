// Package metrics defines the Prometheus metrics in use.
package metrics

import (
	"net"
	"net/http"

	"github.com/cloudflare/cfssl/log"
	"github.com/prometheus/client_golang/prometheus"
)

// QueueCount counts the number of certificates actively in the renewal queue.
var QueueCount = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name: "cert_renewal_queue",
		Help: "number of certificates in the renewal queue",
	},
)

// ExpireNext contains the time of the next certificate expiry.
var ExpireNext = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name: "cert_next_expires",
		Help: "the number of hours until the next certificate expires",
	},
)

// FailureCount contains a count of the number of failures to generate
// a key pair or renew a certificate.
var FailureCount = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "cert_renewal_failures",
		Help: "the number of hours until the next certificate expires",
	},
)

func init() {
	prometheus.MustRegister(QueueCount)
	prometheus.MustRegister(ExpireNext)
	prometheus.MustRegister(FailureCount)
}

// Start initialises the Prometheus endpoint if metrics have been
// configured.
func Start(addr, port string) {
	if addr == "" || port == "" {
		log.Warning("metrics: no prometheus address or port configured")
		return
	}

	addr = net.JoinHostPort(addr, port)
	http.Handle("/", prometheus.Handler())

	log.Infof("metrics: starting Prometheus endpoint on http://%s/", addr)
	go func() {
		log.Fatal(http.ListenAndServe(addr, nil))
	}()
}
