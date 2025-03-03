package randomness_common

import "github.com/prometheus/client_golang/prometheus"

var (
	MasterSeedUpdatesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "rand",
			Name:      "master_seed_updates_total",
			Help:      "Total number of master seed updates",
		},
	)
)

func init() {
	prometheus.MustRegister(MasterSeedUpdatesTotal)
}
