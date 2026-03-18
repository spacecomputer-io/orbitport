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

	trngChunksTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "rand_aptos_orb",
			Name:      "trng_chunks_total",
			Help:      "Total number of TRNG chunks returned by Aptos Orbital.",
		},
	)
)

func init() {
	prometheus.MustRegister(requestDuration, requestTotal, trngChunksTotal)
}
