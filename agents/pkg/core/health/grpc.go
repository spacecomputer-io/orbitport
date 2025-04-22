package health

import (
	"context"

	"google.golang.org/grpc/health/grpc_health_v1"
)

type HealthState uint8

const (
	// HealthStateUnknown indicates that the health state is unknown.
	HealthStateUnknown HealthState = iota
	// HealthStateHealthy indicates that the service is healthy.
	HealthStateHealthy
	// HealthStateUnhealthy indicates that the service is unhealthy.
	HealthStateUnhealthy
)

func (state HealthState) ToHealthCheckStatus() grpc_health_v1.HealthCheckResponse_ServingStatus {
	switch state {
	case HealthStateUnknown:
		return grpc_health_v1.HealthCheckResponse_UNKNOWN
	case HealthStateHealthy:
		return grpc_health_v1.HealthCheckResponse_SERVING
	case HealthStateUnhealthy:
		return grpc_health_v1.HealthCheckResponse_NOT_SERVING
	default:
		return grpc_health_v1.HealthCheckResponse_UNKNOWN
	}
}

// / HealthChecker is a function type that checks the health of a service.
type HealthChecker func(ctx context.Context) (HealthState, error)

// / NewHealthServer creates a new HealthServer with the provided HealthChecker.
func NewHealthServer(checker HealthChecker) *HealthServer {
	return &HealthServer{
		checker: checker,
	}
}

// / HealthServer is a gRPC server that implements the health check service.
// / It responds to health check requests with a status of SERVING.
type HealthServer struct {
	grpc_health_v1.UnimplementedHealthServer
	checker HealthChecker
}

// / Check implements the HealthServer interface.
func (s *HealthServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	state, err := s.checker(ctx)
	if err != nil {
		state = HealthStateUnknown
	}
	status := state.ToHealthCheckStatus()
	return &grpc_health_v1.HealthCheckResponse{Status: status}, nil
}
