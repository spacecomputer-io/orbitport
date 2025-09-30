package aptosorbital

import "github.com/prometheus/client_golang/prometheus"

var (
	requestDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "rand_aptos_orb",
			Name:      "req_duration",
			Help:      "Duration of requests to the Aptos Orbital API",
			Buckets:   prometheus.DefBuckets,
		},
	)
	requestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "rand_aptos_orb",
			Name:      "req_total",
			Help:      "Total number of requests to the Aptos Orbital API",
		},
		[]string{"status"},
	)

	ctrngFallbackTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "ctrng_fallback_total",
			Help:      "Total number of CTRNG values served from fallback (BIP32 master seeds).",
		},
		[]string{"beacon"},
	)

	ctrngFreshTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "ctrng_fresh_total",
			Help:      "Total number of CTRNG values served directly from Aptos (fresh).",
		},
		[]string{"beacon"},
	)
)

func init() {
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(ctrngFallbackTotal, ctrngFreshTotal)
	prometheus.MustRegister(requestTotal)
}
