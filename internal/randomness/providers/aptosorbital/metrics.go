package aptosorbital

import "github.com/prometheus/client_golang/prometheus"

const (
	authStatusAuthenticated  float64 = 1.0
	authStatusBadRequest     float64 = -1.0
	authStatusBadEndpoint    float64 = -2.0
	authStatusFailedResponse float64 = -3.0
	authStatusBadResponse    float64 = -4.0
)

var (
	authStatusCollector = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "sg",
			Subsystem: "rand_aptos_orb",
			Name:      "auth_status",
			Help:      "Status of the Aptos Orbital API authentication",
		},
	)
	authExpireCollector = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "sg",
			Subsystem: "rand_aptos_orb",
			Name:      "auth_expire",
			Help:      "Expiration time of the Aptos Orbital API access token",
		},
	)
	requestDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "sg",
			Subsystem: "rand_aptos_orb",
			Name:      "req_duration",
			Help:      "Duration of requests to the Aptos Orbital API",
			Buckets:   prometheus.DefBuckets,
		},
	)
	requestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "sg",
			Subsystem: "rand_aptos_orb",
			Name:      "req_total",
			Help:      "Total number of requests to the Aptos Orbital API",
		},
		[]string{"status"},
	)
)

func init() {
	prometheus.MustRegister(authStatusCollector)
	prometheus.MustRegister(authExpireCollector)
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(requestTotal)
}
