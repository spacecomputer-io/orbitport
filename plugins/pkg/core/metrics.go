package core

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
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
		[]string{"plugin", "method", "code", "context"},
	)

	pluginRPCDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "op",
			Subsystem: "plugin",
			Name:      "rpc_duration_seconds",
			Help:      "Duration of plugin gRPC requests in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"plugin", "method", "code", "context"},
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

		contextValue := metricContext(req)

		code := strings.ToLower(status.Code(err).String())
		pluginRPCRequestsTotal.WithLabelValues(plugin, method, code, contextValue).Inc()
		pluginRPCDurationSeconds.WithLabelValues(plugin, method, code, contextValue).Observe(time.Since(started).Seconds())

		return resp, err
	}
}

// The UnaryMetricsInterceptor calls this function to extract a metric label value
// (we call it context in our monitoring system)

func metricContext(req any) string {
	switch typedReq := req.(type) {
	case *proto.CreateKeyRequest:
		algorithm := typedReq.GetKeySpec()

		switch algorithm {
		case "AES_256_GCM96",
			"ECC_SECG_P256K1",
			"ECDSA_P256",
			"ECDSA_P384",
			"ED25519",
			"RSA_4096",
			"ML_DSA_44",
			"ML_DSA_65",
			"ML_DSA_87",
			"ML_KEM_768",
			"ML_KEM_1024":
			return algorithm
		default:
			return "other"
		}

	case *proto.SignRequest:
		algorithm := typedReq.GetSigningAlgorithm()

		switch algorithm {
		case "ECDSA_SHA_256",
			"ECDSA_SHA_384",
			"ED25519",
			"RSASSA_PKCS1_V1_5_SHA_256",
			"RSASSA_PSS_SHA_256",
			"ETHEREUM_SECP256K1",
			"ML_DSA":
			return algorithm
		default:
			return "other"
		}

	default:
		return "none"
	}
}

func shouldSkipRPCMetrics(fullMethod string) bool {
	return strings.HasPrefix(fullMethod, "/grpc.health.v1.Health/")
}
