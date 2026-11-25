package kms

import "github.com/prometheus/client_golang/prometheus"

var (
	deletedKeys = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "orbitport",
			Subsystem: "kms",
			Name:      "deleted_keys_total",
			Help:      "Completed scheduled key deletion attempts.",
		},
	)
	failedDeletions = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "orbitport",
			Subsystem: "kms",
			Name:      "failed_deletions_total",
			Help:      "Scheduled deletion backend or integrity failures.",
		},
	)
)

func init() {
	prometheus.MustRegister(deletedKeys, failedDeletions)
}
