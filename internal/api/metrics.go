package gateway_api

import "github.com/prometheus/client_golang/prometheus"

var (
	RandRequestDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "sg",
			Subsystem: "rand",
			Name:      "req_duration",
			Help:      "Duration of rand requests as they pass through the gateway",
			Buckets:   prometheus.DefBuckets,
		},
	)
	RandRequestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sg",
			Subsystem: "rand",
			Name:      "req_total",
			Help:      "Total number of rand requests to the gateway",
		},
		[]string{"status"},
	)
)

func init() {
	prometheus.MustRegister(RandRequestDuration)
	prometheus.MustRegister(RandRequestTotal)
}
