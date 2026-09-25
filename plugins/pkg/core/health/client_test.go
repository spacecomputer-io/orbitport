package health

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func serveHealth(t *testing.T, state HealthState) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	healthpb.RegisterHealthServer(s, NewHealthServer(func(context.Context) (HealthState, error) {
		return state, nil
	}))
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return lis.Addr().String()
}

func TestCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := Check(ctx, serveHealth(t, HealthStateHealthy)); err != nil {
		t.Fatalf("healthy server: %v", err)
	}
	if err := Check(ctx, serveHealth(t, HealthStateUnhealthy)); err == nil {
		t.Fatal("unhealthy server: expected an error")
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := lis.Addr().String()
	_ = lis.Close()
	if err := Check(ctx, closed); err == nil {
		t.Fatal("closed port: expected an error")
	}
}
