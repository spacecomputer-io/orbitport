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
			Namespace: "op",
			Subsystem: "health",
			Name:      "status",
			Help:      "Status of the gateway health",
		},
	)
)

func init() {
	prometheus.MustRegister(gatewayHealthStatus)
}
