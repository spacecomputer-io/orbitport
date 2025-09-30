package ipfs

import "github.com/prometheus/client_golang/prometheus"

var (
	addDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "add_duration_seconds",
			Help:      "Total time to add (and pin & cache) a block with Add RPC",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"status"},
	)

	addBytes = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "add_bytes",
			Help:      "Size of payloads added with Add RPC",
			Buckets:   prometheus.ExponentialBuckets(256, 2, 12),
		},
	)

	addTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "add_total",
			Help:      "Total Add RPC attempts",
		},
		[]string{"status"},
	)

	getDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "get_duration_seconds",
			Help:      "End-to-end time of Get RPC (including cache check, resolve, fetch, read)",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"source", "namespace", "status"}, // source=cache|ipfs, namespace=ipfs|ipns, status=ok|err
	)

	getBytes = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "get_bytes",
			Help:      "Size of payloads returned by Get",
			Buckets:   prometheus.ExponentialBuckets(256, 2, 12),
		},
		[]string{"source", "namespace"},
	)

	getTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "get_total",
			Help:      "Total Get RPC attempts",
		},
		[]string{"source", "namespace", "status"},
	)

	publishDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "publish_duration_seconds",
			Help:      "End-to-end time of Publish RPC",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"status"},
	)

	publishTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "publish_total",
			Help:      "Total Publish RPC attempts",
		},
		[]string{"status"},
	)

	deleteDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "delete_duration_seconds",
			Help:      "End-to-end time of Delete RPC",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"status"},
	)

	deleteTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "delete_total",
			Help:      "Total Delete RPC attempts",
		},
		[]string{"status"},
	)

	rpcDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "rpc_duration_seconds",
			Help:      "Latency of individual IPFS RPC calls",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"rpc"}, // block_put|pin_add|name_resolve|block_get|name_publish|key_list|key_generate|pin_rm|block_rm
	)

	rpcTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "rpc_total",
			Help:      "Total IPFS RPC attempts",
		},
		[]string{"rpc", "status"},
	)

	cacheHitsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "cache_hits_total",
			Help:      "Cache hits by namespace",
		},
		[]string{"namespace"}, // ipfs|ipns (for ipns name-resolution cache, 'ipns'; for data cache, 'ipfs')
	)

	cacheMissesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "cache_misses_total",
			Help:      "Cache misses by namespace",
		},
		[]string{"namespace"},
	)

	cacheItems = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "op",
			Subsystem: "ipfs",
			Name:      "cache_items",
			Help:      "Current items stored in caches",
		},
		[]string{"kind"}, // data|ipns
	)
)

func init() {
	prometheus.MustRegister(
		addDuration, addBytes, addTotal,
		getDuration, getBytes, getTotal,
		publishDuration, publishTotal,
		deleteDuration, deleteTotal,
		rpcDuration, rpcTotal,
		cacheHitsTotal, cacheMissesTotal, cacheItems,
	)
}

func (p *Plugin) RegisterCacheGauges() {
	// initialize once (will be updated in code paths)
	cacheItems.WithLabelValues("data").Set(float64(p.cache.Len()))
	cacheItems.WithLabelValues("ipns").Set(float64(p.ipnsCache.Len()))
}
