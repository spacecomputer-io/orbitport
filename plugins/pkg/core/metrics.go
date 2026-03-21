package core

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

var (
	pluginRPCRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "op",
			Subsystem: "plugin",
			Name:      "rpc_requests_total",
			Help:      "Total number of plugin gRPC requests.",
		},
		[]string{"plugin", "method", "code"},
	)

	pluginRPCDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "plugin",
			Name:      "rpc_duration_seconds",
			Help:      "Duration of plugin gRPC requests in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"plugin", "method", "code"},
	)
)

func init() {
	prometheus.MustRegister(pluginRPCRequestsTotal, pluginRPCDurationSeconds)
}

// UnaryMetricsInterceptor records per-plugin gRPC request counts and latency.
func UnaryMetricsInterceptor(plugin string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if shouldSkipRPCMetrics(info.FullMethod) {
			return handler(ctx, req)
		}

		method := path.Base(info.FullMethod)
		started := time.Now()

		resp, err := handler(ctx, req)

		code := strings.ToLower(status.Code(err).String())
		pluginRPCRequestsTotal.WithLabelValues(plugin, method, code).Inc()
		pluginRPCDurationSeconds.WithLabelValues(plugin, method, code).Observe(time.Since(started).Seconds())

		return resp, err
	}
}

func shouldSkipRPCMetrics(fullMethod string) bool {
	return strings.HasPrefix(fullMethod, "/grpc.health.v1.Health/")
}
