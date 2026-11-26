package kms

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestDeletionMetricsRegistered(t *testing.T) {
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	expected := map[string]string{
		"orbitport_kms_deleted_keys_total":     "Completed scheduled key deletion attempts.",
		"orbitport_kms_failed_deletions_total": "Scheduled deletion backend or integrity failures.",
	}
	for _, family := range families {
		help, ok := expected[family.GetName()]
		if !ok {
			continue
		}
		require.Equal(t, help, family.GetHelp())
		require.Equal(t, "COUNTER", family.GetType().String())
		require.Len(t, family.Metric, 1)
		require.Empty(t, family.Metric[0].Label)
		delete(expected, family.GetName())
	}
	require.Empty(t, expected, "deletion metrics must be registered with their existing names")
}
