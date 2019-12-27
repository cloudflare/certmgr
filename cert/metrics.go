package cert

import (
	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "certmgr"

var (
	// SpecExpires contains the time of the next certificate
	// expiry.
	SpecExpires = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "expire_timestamp",
			Help:      "The unix time for when the given spec and PKI type expires",
		},
		[]string{"name", "type"},
	)

	// SpecExpiresBeforeThreshold exports how much lead time we give for trying to renew a cert
	// before it expires.
	SpecExpiresBeforeThreshold = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "expire_before_duration_seconds",
			Help:      "When a spec is within this number of seconds of an expiry, renewal begins",
		},
		[]string{"name"},
	)

	// SpecWriteCount contains the number of times the PKI on disk was written
	SpecWriteCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "write_count",
			Help:      "The number of times PKI on disk has been rewritten",
		},
		[]string{"name"},
	)

	// SpecWriteFailureCount contains the number of times the PKI on disk failed to be written
	SpecWriteFailureCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "write_failure_count",
			Help:      "The number of times PKI on disk failed to be rewritten",
		},
		[]string{"name"},
	)

	// SpecRequestFailureCount counts the number of times a spec failed to request a certificate from upstream.
	SpecRequestFailureCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "request_failure_count",
			Help:      "Number of failed requests to CA authority for new PKI material",
		},
		[]string{"name"},
	)

	// SpecNextWake is set to the timestamp of the next wakeup to check and enforce a spec.
	SpecNextWake = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "spec_next_wake_timestamp",
			Help:      "The epoch value of when this spec will next awaken to perform checks",
		},
		[]string{"name"},
	)
)

func init() {
	prometheus.MustRegister(SpecExpires)
	prometheus.MustRegister(SpecExpiresBeforeThreshold)
	prometheus.MustRegister(SpecWriteCount)
	prometheus.MustRegister(SpecWriteFailureCount)
	prometheus.MustRegister(SpecRequestFailureCount)
	prometheus.MustRegister(SpecNextWake)
}

// WipeMetrics Wipes any metrics that may be recorded for this spec.
// In general this should be invoked only when a spec is being removed from tracking.
func (spec *Spec) WipeMetrics() {
	SpecExpiresBeforeThreshold.DeleteLabelValues(spec.Name)
	SpecNextWake.DeleteLabelValues(spec.Name)
	SpecWriteCount.DeleteLabelValues(spec.Name)
	SpecWriteFailureCount.DeleteLabelValues(spec.Name)
	SpecRequestFailureCount.DeleteLabelValues(spec.Name)
	for _, t := range []string{"ca", "cert", "key"} {
		SpecExpires.DeleteLabelValues(spec.Name, t)
	}
}
