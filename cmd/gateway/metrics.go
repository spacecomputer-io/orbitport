package main

import "github.com/prometheus/client_golang/prometheus"

const (
	healthStatusDown     float64 = 0.0
	healthStatusStarting float64 = 1.0
	healthStatusReady    float64 = 2.0
)

var (
	gatewayHealthStatus = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "sg",
			Subsystem: "health",
			Name:      "status",
			Help:      "Status of the gateway health",
		},
	)
	randRequestDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "sg",
			Subsystem: "rand",
			Name:      "req_duration",
			Help:      "Duration of rand requests as they pass through the gateway",
			Buckets:   prometheus.DefBuckets,
		},
	)
	randRequestTotal = prometheus.NewCounterVec(
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
	prometheus.MustRegister(gatewayHealthStatus)
	prometheus.MustRegister(randRequestDuration)
	prometheus.MustRegister(randRequestTotal)
}
