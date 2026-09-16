package openbao

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
)

//define metricLabelsKey (key) and MetricLabels (Value) so that these can be added to context
//which then gets passed to do

type MetricLabels struct {
	Operation     string
	Algorithm     string
	CommitteeSize string
}

type metricLabelsKey struct{}

func WithMetricLabels(ctx context.Context, labels MetricLabels) context.Context {
	return context.WithValue(ctx, metricLabelsKey{}, labels)
}

var (
	openbaoDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "openbao",
			Name:      "duration_seconds",
			Buckets:   prometheus.DefBuckets,
			Help:      "OpenBao roundtrip time in seconds",
		},
		[]string{"operation", "algorithm", "committee_size", "status"},
	)
)

func init() {
	prometheus.MustRegister(
		openbaoDurationSeconds,
	)
}
