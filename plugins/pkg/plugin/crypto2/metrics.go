package crypto2

import "github.com/prometheus/client_golang/prometheus"

var (
	requestDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "rand_crypto2",
			Name:      "req_duration",
			Help:      "Duration of requests to the Crypto2 API",
			Buckets:   prometheus.DefBuckets,
		},
	)
	requestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "rand_crypto2",
			Name:      "req_total",
			Help:      "Total number of requests to the Crypto2 API",
		},
		[]string{"status"},
	)

	trngChunksTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "rand_crypto2",
			Name:      "trng_chunks_total",
			Help:      "Total number of TRNG chunks returned by Crypto2.",
		},
	)

	trngBytesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "rand_crypto2",
			Name:      "trng_bytes_total",
			Help:      "Total number of TRNG bytes returned by Crypto2.",
		},
	)

	trngChunksPerRequest = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "rand_crypto2",
			Name:      "trng_chunks_per_request",
			Help:      "Distribution of TRNG chunks returned per successful Crypto2 request.",
			Buckets:   []float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 1500},
		},
	)
)

func init() {
	prometheus.MustRegister(
		requestDuration,
		requestTotal,
		trngChunksTotal,
		trngBytesTotal,
		trngChunksPerRequest,
	)
}
