package cert

import (
	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "certmgr"

var (
	// SpecRefreshCount counts the number of PKI regeneration taken by a spec
	SpecRefreshCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "refresh_count",
			Help:      "Number of times a spec has determined PKI must be refreshed",
		},
		[]string{"spec_path"},
	)

	// SpecCheckCount counts the number of PKI regeneration taken by a spec
	SpecCheckCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "check_count",
			Help:      "Number of times a spec PKI was checked",
		},
		[]string{"spec_path"},
	)

	// SpecExpires contains the time of the next certificate
	// expiry.
	SpecExpires = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "expire_timestamp",
			Help:      "The unix time for when the given spec and PKI type expires",
		},
		[]string{"spec_path", "type"},
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
		[]string{"spec_path"},
	)

	// SpecWriteCount contains the number of times the PKI on disk was written
	SpecWriteCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "write_count",
			Help:      "The number of times PKI on disk has been rewritten",
		},
		[]string{"spec_path"},
	)

	// SpecWriteFailureCount contains the number of times the PKI on disk failed to be written
	SpecWriteFailureCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "write_failure_count",
			Help:      "The number of times PKI on disk failed to be rewritten",
		},
		[]string{"spec_path"},
	)

	// SpecRequestFailureCount counts the number of times a spec failed to request a certificate from upstream.
	SpecRequestFailureCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "request_failure_count",
			Help:      "Number of failed requests to CA authority for new PKI material",
		},
		[]string{"spec_path"},
	)

	// SpecNextWake is set to the timestamp of the next wakeup to check and enforce a spec.
	SpecNextWake = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: "spec",
			Name:      "spec_next_wake_timestamp",
			Help:      "The epoch value of when this spec will next awaken to perform checks",
		},
		[]string{"spec_path"},
	)

	// ActionAttemptedCount counts actions taken by a spec
	ActionAttemptedCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "action_attempted_count",
			Help:      "Number of times a spec has taken action",
		},
		[]string{"spec_path", "change_type"},
	)

	// ActionFailedCount counts failed actions taken by a spec
	ActionFailedCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "action_failed_count",
			Help:      "Number of failed action runs for a spec",
		},
		[]string{"spec_path", "change_type"},
	)
)

func init() {
	prometheus.MustRegister(SpecRefreshCount)
	prometheus.MustRegister(SpecCheckCount)
	prometheus.MustRegister(SpecExpires)
	prometheus.MustRegister(SpecExpiresBeforeThreshold)
	prometheus.MustRegister(SpecWriteCount)
	prometheus.MustRegister(SpecWriteFailureCount)
	prometheus.MustRegister(SpecRequestFailureCount)
	prometheus.MustRegister(SpecNextWake)
	prometheus.MustRegister(ActionAttemptedCount)
	prometheus.MustRegister(ActionFailedCount)
}

// WipeMetrics Wipes any metrics that may be recorded for this spec.
// In general this should be invoked only when a spec is being removed from tracking.
func (spec *Spec) WipeMetrics() {
	SpecRefreshCount.DeleteLabelValues(spec.Path)
	SpecCheckCount.DeleteLabelValues(spec.Path)
	SpecExpiresBeforeThreshold.DeleteLabelValues(spec.Path)
	SpecNextWake.DeleteLabelValues(spec.Path)
	SpecWriteCount.DeleteLabelValues(spec.Path)
	SpecWriteFailureCount.DeleteLabelValues(spec.Path)
	SpecRequestFailureCount.DeleteLabelValues(spec.Path)
	for _, t := range []string{"ca", "cert", "key"} {
		SpecExpires.DeleteLabelValues(spec.Path, t)
		ActionAttemptedCount.DeleteLabelValues(spec.Path, t)
		ActionFailedCount.DeleteLabelValues(spec.Path, t)
	}
}
