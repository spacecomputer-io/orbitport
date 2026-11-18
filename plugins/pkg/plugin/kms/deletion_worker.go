package kms

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Start runs one non-overlapping, cancellable sweep loop per plugin instance.
func (p *Plugin) Start(ctx context.Context) {
	p.startOnce.Do(func() {
		if p.deletionInterval == 0 {
			return
		}
		p.threads.GoCtx(ctx, func(ctx context.Context) {
			timer := time.NewTimer(deletionJitter(p.deletionInterval))
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					p.sweepDeletedKeys(ctx)
					timer.Reset(deletionJitter(p.deletionInterval))
				}
			}
		})
	})
}

func (p *Plugin) Close() {
	p.closeOnce.Do(func() { p.threads.Close() })
}

// Jitter spreads replicas without polling or keeping a dedicated OS thread busy.
func deletionJitter(interval time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(1001))
	if err != nil {
		return interval
	}
	return interval + interval/10000*time.Duration(n.Int64()-500)
}

func parseDeletionEntry(entry string) (string, time.Time, error) {
	parts := strings.Split(entry, "_")
	if len(parts) != 3 || !isCanonicalKeyID(parts[0]) || len(parts[2]) != 8 {
		return "", time.Time{}, fmt.Errorf("invalid deletion index entry")
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return "", time.Time{}, fmt.Errorf("invalid deletion index suffix")
	}
	deadline, err := time.Parse("20060102T150405Z", parts[1])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invalid deletion index deadline")
	}
	return parts[0], deadline, nil
}

func (p *Plugin) sweepDeletedKeys(ctx context.Context) {
	tenants, err := p.client.pendingDeletionTenants(ctx)
	if err != nil {
		failedDeletions.Inc()
		logger.Warnf("could not list pending deletions: %v", err)
		return
	}
	for _, tenant := range tenants {
		if ctx.Err() != nil {
			return
		}
		entries, err := p.client.listKMSMetadata(ctx, tenant, "pending-deletion")
		if err != nil {
			failedDeletions.Inc()
			logger.Warnf("could not list pending deletions tenant=%s: %v", tenant, err)
			continue
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				return
			}
			keyID, deadline, err := parseDeletionEntry(entry)
			if err != nil {
				logger.Warnf("skipping unsafe deletion entry tenant=%s entry=%q", tenant, entry)
				continue
			}
			if p.now().UTC().Before(deadline) {
				continue
			}
			keyCtx, cancel := context.WithTimeout(ctx, time.Minute)
			err = p.deleteScheduledKey(keyCtx, tenant, entry, keyID, deadline)
			cancel()
			if err != nil {
				failedDeletions.Inc()
				logger.Warnf("scheduled deletion failed tenant=%s key_id=%s: %v", tenant, keyID, err)
			}
		}
	}
}

func (p *Plugin) deleteScheduledKey(ctx context.Context, tenant, entry, keyID string, deadline time.Time) error {
	target, err := p.client.kmsMetadataURL(tenant, "metadata", keyID, false)
	if err != nil {
		return err
	}
	record, err := p.client.getMetadataAt(ctx, target)
	if isOpenBaoNotFound(err) {
		return p.client.deleteDeletionEntry(ctx, tenant, entry)
	}
	if err != nil {
		return err
	}
	if record.KeyState != keyStatePendingDeletion || record.DeletionIndex != entry {
		return p.client.deleteDeletionEntry(ctx, tenant, entry)
	}
	expectedBackend, keyErr := scopedBackendKey(record.ClientID, strings.TrimPrefix(keyID, "kms:"))
	recordDate, dateErr := time.Parse(time.RFC3339, record.DeletionDate)
	if record.ClientID == "" || tenantNamespace(record.ClientID) != tenant || record.KeyID != keyID ||
		keyErr != nil || record.backendKey() != expectedBackend || dateErr != nil || !recordDate.Equal(deadline) ||
		!validLifecycleState(record) || record.metadataRevision == 0 {
		return fmt.Errorf("invalid scheduled deletion metadata")
	}
	if record.Scheme != schemeTransit {
		return fmt.Errorf("scheduled deletion supports TRANSIT only")
	}
	provider, err := p.providerForScheme(record.Scheme)
	if err != nil {
		return err
	}
	deleter, err := requireDeleteKeyProvider(provider, record.Scheme)
	if err != nil {
		return err
	}
	if record.DeletionStartedAt == "" {
		record.DeletionStartedAt = p.now().UTC().Format(time.RFC3339)
	}
	if err := p.client.putMetadata(ctx, record.ClientID, keyID, record); err != nil {
		if isMetadataCASConflict(err) {
			return nil
		}
		return err
	}
	if err := p.client.putKeyTombstone(ctx, tenant, record, record.DeletionStartedAt); err != nil {
		return err
	}
	if err := deleter.DeleteKey(ctx, record); err != nil {
		return err
	}
	target, err = p.client.kmsMetadataURL(tenant, "metadata", keyID, true)
	if err != nil {
		return err
	}
	if err := p.client.Delete(ctx, target, nil); err != nil {
		return err
	}
	if err := p.client.deleteDeletionEntry(ctx, tenant, entry); err != nil {
		return err
	}
	deletedKeys.Inc()
	logger.Infof("deleted scheduled key tenant=%s key_id=%s scheme=%s", tenant, keyID, record.Scheme)
	return nil
}
