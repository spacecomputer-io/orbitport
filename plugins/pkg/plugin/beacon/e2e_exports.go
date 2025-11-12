//go:build e2e

package beacon

import "context"

// Narrow surface: expose just what your e2e tests need.
func E2ELoadRegistry(ctx context.Context, cfg Config) (*Registry, error) {
	return loadRegistry(ctx, cfg)
}
