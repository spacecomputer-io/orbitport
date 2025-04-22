package core

import (
	"fmt"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
)

// ListenGrpc starts a grpc server on the given port.
func ListenGrpc(s *grpc.Server, grpcPort uint16) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		return fmt.Errorf("could not create TCP listener: %v", err)
	}
	defer s.Stop()
	if err := s.Serve(lis); err != nil {
		return fmt.Errorf("could not serve grpc: %v", err)
	}
	return nil
}

func ListenMetrics(port uint16) error {
	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	))

	return http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
}
