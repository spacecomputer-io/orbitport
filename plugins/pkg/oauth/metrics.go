package oauth

import "github.com/prometheus/client_golang/prometheus"

const (
	authStatusAuthenticated  float64 = 1.0
	authStatusBadRequest     float64 = -1.0
	authStatusBadEndpoint    float64 = -2.0
	authStatusFailedResponse float64 = -3.0
	authStatusBadResponse    float64 = -4.0
)

var (
	authStatusCollector = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "op",
			Subsystem: "rand_aptos_orb",
			Name:      "auth_status",
			Help:      "Status of the Aptos Orbital API authentication",
		},
		[]string{"endpoint"},
	)
	authExpireCollector = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "op",
			Subsystem: "rand_aptos_orb",
			Name:      "auth_expire",
			Help:      "Expiration time of the Aptos Orbital API access token",
		},
		[]string{"endpoint"},
	)
)

func init() {
	prometheus.MustRegister(authStatusCollector)
	prometheus.MustRegister(authExpireCollector)
}
