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

		contextValue := metricContext(req, resp)

		code := strings.ToLower(status.Code(err).String())
		pluginRPCRequestsTotal.WithLabelValues(plugin, method, code, contextValue).Inc()
		pluginRPCDurationSeconds.WithLabelValues(plugin, method, code, contextValue).Observe(time.Since(started).Seconds())

		return resp, err
	}
}

// The UnaryMetricsInterceptor calls this function to extract a metric label value
// (we call it context in our monitoring system)

func metricContext(req any, response any) string {

	//the decrypt case I handle as a response type because the user usually provides a cyphertext "blob" as a
	//decryptRequest but this contains the values encoded as b64, so orbitport then returns the decrypted values

	switch typedResponse := response.(type) {
	case *proto.DecryptResponse:
		algorithm := typedResponse.EncryptionAlgorithm
		if algorithm == "" {
			return "unknown"
		}
		return algorithm
	case *proto.EncryptResponse:
		algorithm := typedResponse.EncryptionAlgorithm
		if algorithm == "" {
			return "unknown"
		}
		return algorithm
	case *proto.RotateKeyResponse:
		metadata := typedResponse.GetKeyMetadata()
		if metadata != nil {
			algorithm := metadata.KeySpec
			if algorithm == "" {
				return "unknown"
			}
			return algorithm
		}
		return "unknown"
	}

	switch typedReq := req.(type) {
	case *proto.CreateKeyRequest:
		algorithm := typedReq.KeySpec
		if algorithm == "" {
			return "unknown"
		}
		return algorithm
	case *proto.EncryptRequest:
		algorithm := typedReq.GetEncryptionAlgorithm()
		if algorithm == "" {
			return "unknown"
		}
		return algorithm
	case *proto.SignRequest:
		algorithm := typedReq.GetSigningAlgorithm()
		if algorithm == "" {
			return "unknown"
		}
		return algorithm

	case *proto.DecryptRequest:
		return "unknown"

	case *proto.GenerateDataKeyRequest:
		algorithm := typedReq.GetDataKeySpec()
		if algorithm == "" {
			//in the proto file the user can give the algorithim as optional, or instead the number of bytes
			//so if the alogrithim is not given we should give "by_bytes" instead
			return "by_bytes"
		}
		return algorithm

	default:
		return "none"
	}
}

func shouldSkipRPCMetrics(fullMethod string) bool {
	return strings.HasPrefix(fullMethod, "/grpc.health.v1.Health/")
}
