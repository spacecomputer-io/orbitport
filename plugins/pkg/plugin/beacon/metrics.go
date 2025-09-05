package beacon

import "github.com/prometheus/client_golang/prometheus"

var (
	execDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "exec_duration_seconds",
			Help:      "Total time to build, add annd publish one beacon block",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"beacon"},
	)

	execTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "exec_total",
			Help:      "Total executions of beacon builds",
		},
		[]string{"beacon", "status"},
	)

	loadLastDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "load_last_block_duration_seconds",
			Help:      "Duration to load and unmarshal the last beacon block",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"beacon"},
	)

	loadLastTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "load_last_block_total",
			Help:      "Total attempts to load the last beacon block",
		},
		[]string{"beacon", "status"},
	)

	ctrngDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "ctrng_load_duration_seconds",
			Help:      "Timee to get CTRNG values for a beacon execution",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"beacon"},
	)

	ctrngTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "ctrng_load_total",
			Help:      "Total CTRNG retrieval attempts (per beacon execution)",
		},
		[]string{"beacon", "status"},
	)

	ipfsAddDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "ipfs_add_duration_seconds",
			Help:      "Duration of ipfs add of a beacon block",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"beacon"},
	)

	ipfsAddTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "ipfs_add_total",
			Help:      "Total ipfs add attempts of beacon block",
		},
		[]string{"beacon", "status"},
	)

	ipnsPublishDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "ipns_publish_duration_seconds",
			Help:      "Duration of IPNS publish of block to beacon",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"beacon"},
	)

	ipnsPublishTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "ipns_publish_total",
			Help:      "Total IPNS publish attempts of block to beacon",
		},
		[]string{"beacon", "status"},
	)

	schedTickTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "scheduler_tick_total",
			Help:      "Number of periodic scheduler ticks",
		},
	)

	scheduledExecutionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "scheduled_executions_total",
			Help:      "Number of beacon executions scheduled",
		},
		[]string{"beacon"},
	)

	skippedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "skipped_total",
			Help:      "Number of beacons execeutions skipped by scheduler",
		},
		[]string{"beacon", "reason"},
	)

	lastSequence = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "last_sequence",
			Help:      "Last published sequence number observed locally",
		},
		[]string{"beacon"},
	)

	lastTimestampSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "last_timestamp_seconds",
			Help:      "Last published beacon block timestamp (seconds since epoch)",
		},
		[]string{"beacon"},
	)

	genesisStepTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "genesis_step_total",
			Help:      "Steps during two-step genesis: temp_add|temp_publish|final_add|final_publish",
		},
		[]string{"beacon", "step", "status"},
	)

	genesisStepDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "genesis_step_duration_seconds",
			Help:      "Duration of each genesis step",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"beacon", "step"},
	)
)

var (
	// queueDepth is a GaugeFunc registered dynamically from the Scheduler
	queueDepth prometheus.GaugeFunc
)

// RegisterQueueDepthGauge sets up the gauge for queue depth.
func RegisterQueueDepthGauge(getLen func() float64) {
	queueDepth = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: "op",
			Subsystem: "beacon",
			Name:      "queue_depth",
			Help:      "Current number of queued beacon executions",
		},
		getLen,
	)
	prometheus.MustRegister(queueDepth)
}

func init() {
	prometheus.MustRegister(execDuration, execTotal)
	prometheus.MustRegister(loadLastDuration, loadLastTotal)
	prometheus.MustRegister(ctrngDuration, ctrngTotal)
	prometheus.MustRegister(ipfsAddDuration, ipfsAddTotal)
	prometheus.MustRegister(ipnsPublishDuration, ipnsPublishTotal)
	prometheus.MustRegister(schedTickTotal, scheduledExecutionsTotal)
	prometheus.MustRegister(lastSequence, lastTimestampSeconds)
	prometheus.MustRegister(queueDepth)
	prometheus.MustRegister(genesisStepTotal, genesisStepDuration)
}
