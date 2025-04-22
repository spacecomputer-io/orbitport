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
)

func init() {
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(requestTotal)
}
