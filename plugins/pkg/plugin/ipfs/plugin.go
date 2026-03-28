package ipfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/ipfs/boxo/ipns"
	"github.com/ipfs/boxo/path"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/kubo/client/rpc"
	iface "github.com/ipfs/kubo/core/coreiface"
	"github.com/ipfs/kubo/core/coreiface/options"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	pluginsproto "github.com/spacecomputer-io/orbitport/plugins/proto"
)

type Plugin struct {
	pluginsproto.IpfsPluginServer

	node      *rpc.HttpApi
	cache     *lru.Cache
	ipnsCache *lru.Cache

	leaseDuration time.Duration
	maxAddBytes   uint
	maxGetBytes   uint
}

// NewPlugin creates a new IPFS plugin with a storage layer.
func NewPlugin() (*Plugin, error) {
	cfg := readFromEnv()

	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("creating plugin with config: %+v", cfg)

	addr, err := convertToMultiaddr(cfg.IPFSAddress)
	if err != nil {
		logger.Warnf("failed to convert IPFS address: %s", err)
		return nil, err
	}

	multiAddr, err := ma.NewMultiaddr(addr)
	if err != nil {
		logger.Warnf("failed to parse IPFS address: %s", err)
		return nil, err
	}

	node, err := rpc.NewApi(multiAddr)
	if err != nil {
		logger.Warnf("failed to create IPFS node: %s", err)
		return nil, err
	}

	logger.Info("IPFS plugin created")

	cache, err := lru.New(int(cfg.CacheSize))
	if err != nil {
		logger.Warnf("failed to create cache: %s", err)
		return nil, err
	}

	ipnsCache, err := lru.New(int(cfg.CacheSize / 2))
	if err != nil {
		logger.Warnf("failed to create IPNS cache: %s", err)
		return nil, err
	}

	pl := &Plugin{
		node:          node,
		cache:         cache,
		ipnsCache:     ipnsCache,
		leaseDuration: cfg.LeaseDuration,
		maxAddBytes:   cfg.MaxAddBytes,
		maxGetBytes:   cfg.MaxGetBytes,
	}

	pl.RegisterCacheGauges()
	return pl, nil
}

// Add implements the Add RPC method.
func (pi *Plugin) Add(ctx context.Context, req *pluginsproto.AddRequest) (*pluginsproto.AddResponse, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Info("Adding data to IPFS")

	start := time.Now()
	status := "ok"
	defer func() {
		addDuration.WithLabelValues(status).Observe(time.Since(start).Seconds())
		addTotal.WithLabelValues(status).Inc()
	}()

	addBytesTotal.Add(float64(len(req.Data)))

	if uint(len(req.Data)) > pi.maxAddBytes {
		status = "err"
		err := fmt.Errorf("add payload too large: %d bytes exceeds max %d", len(req.Data), pi.maxAddBytes)
		logger.Warn(err.Error())
		return nil, err
	}

	block, err := pi.node.Block().Put(ctx, bytes.NewReader(req.Data))
	if err != nil {
		status = "err"
		logger.Warnf("failed to add data: %s", err)
		return nil, err
	}

	// pin the added block
	if err := pi.node.Pin().Add(ctx, block.Path()); err != nil {
		status = "err"
		logger.Warnf("failed to pin cid (%s): %s", block.Path().RootCid(), err)
		return nil, err
	}

	path := block.Path()

	logger.Debugf("caching data for path: %s. Data size: %d", path.String(), len(req.Data))
	// add to cache
	pi.cache.Add(path.String(), req.Data)
	cacheItems.WithLabelValues("data").Set(float64(pi.cache.Len()))

	resp := &pluginsproto.AddResponse{
		Cid: path.RootCid().String(),
	}

	return resp, nil
}

// Get implements the Get RPC method.
// normalization of alias, bare peerID or "/ipns/<peerID>" prevents DNSLink misroutes
// normalized value is always canonical /ipns/<peerID>
func (pi *Plugin) Get(ctx context.Context, req *pluginsproto.GetRequest) (*pluginsproto.GetResponse, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("Getting data from IPFS for key: %s. Namespace: %s", req.Key, req.Namespace)

	source := "ipfs"
	status := "ok"
	start := time.Now()
	defer func() {
		getDuration.WithLabelValues(source, req.Namespace, status).Observe(time.Since(start).Seconds())
	}()

	var p path.Path
	switch req.Namespace {
	case "ipfs":
		// resolve by cid
		cid, err := cid.Decode(req.Key)
		if err != nil {
			status = "err"
			getTotal.WithLabelValues(source, req.Namespace, status).Inc()
			logger.Warnf("failed to decode cid (%s): %s", req.Key, err)
			return nil, err
		}
		p = path.FromCid(cid)

	case "ipns":
		{
			// value can be: alias, bare peerID or "/ipns/<peerID>", depending on caller
			name := req.Key

			// Fast path: cache on the exact key provided
			if resolved, ok := pi.ipnsCache.Get(name); ok {
				cacheHitsTotal.WithLabelValues("ipns").Inc()
				p = resolved.(path.Path)
				break
			}
			cacheMissesTotal.WithLabelValues("ipns").Inc()

			// Normalize to a "/ipns/<peerID>" path
			normalized := name
			if !strings.HasPrefix(normalized, "/ipns/") {
				if key, err := pi.keyForName(ctx, normalized); err == nil {
					// structure is "/ipns/<peerID>"
					kpath := key.Path().String()
					if kpath != "" {
						normalized = kpath
					} else {
						// fallback: treat input as bare peerID
						normalized = "/ipns/" + normalized
					}
				} else {
					// not a local alias. treat as bare peerID
					normalized = "/ipns/" + normalized
				}
			}

			// Resolve to current /ipfs/<cid> head
			resolved, err := pi.node.Name().Resolve(ctx, normalized)
			if err != nil {
				status = "err"
				getTotal.WithLabelValues(source, req.Namespace, status).Inc()
				logger.Warnf("failed to resolve name %q: %s", normalized, err)
				logger.Warnf(
					"IPNS resolve failed: reqKey=%q normalized=%q err=%s errType=%T",
					name, normalized, err.Error(), err,
				)

				logErrorChain(logger, err)

				return nil, err
			}
			p = resolved

			// Caching under both the normalized path and the original request key assures consistency and high performance (fast lookup)
			pi.ipnsCache.Add(normalized, p)
			pi.ipnsCache.Add(name, p)
			cacheItems.WithLabelValues("ipns").Set(float64(pi.ipnsCache.Len()))
			logger.Debugf("resolved path for name: %s", normalized)
		}

	default:
		status = "err"
		getTotal.WithLabelValues(source, req.Namespace, status).Inc()
		logger.Warnf("unknown namespace: %s", req.Namespace)
		return nil, fmt.Errorf("unknown namespace: %s", req.Namespace)
	}

	logger.Debugf("resolved path: %s", p.String())

	// get the data (will also hit the block cache if present)
	data, err := pi.getByPath(ctx, p, req.Namespace)
	if err != nil {
		logger.Warnf("failed to get data with path <%s>: %s", p.String(), err)
		return nil, err
	}

	getBytesTotal.Add(float64(len(data)))

	return &pluginsproto.GetResponse{
		Data: data,
		Path: p.String(),
	}, nil
}

func (pi *Plugin) Publish(ctx context.Context, req *pluginsproto.PublishRequest) (*pluginsproto.PublishResponse, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("Publishing %s on IPNS (%s)", req.Cid, req.PublishName)

	status := "ok"
	start := time.Now()
	defer func() {
		publishDuration.WithLabelValues(status).Observe(time.Since(start).Seconds())
		publishTotal.WithLabelValues(status).Inc()
	}()

	key, err := pi.resolveOrGenerateKey(ctx, req.PublishName)
	if err != nil {
		status = "err"
		return nil, err
	}
	cid, err := cid.Decode(req.Cid)
	if err != nil {
		status = "err"
		logger.Warnf("failed to decode cid (%s): %s", req.Cid, err)
		return nil, err
	}

	updatedName, err := pi.publish(ctx, path.FromCid(cid), key.Name())
	if err != nil {
		status = "err"

		logger.Warnf("failed to publish (%s): %s", key.Name(), err)
		return nil, err
	}
	logger.Infof("published %s", updatedName)
	return &pluginsproto.PublishResponse{
		IpnsName: updatedName.String(),
	}, nil
}

// Delete implements the Delete RPC method.
func (pi *Plugin) Delete(ctx context.Context, req *pluginsproto.DeleteRequest) (*pluginsproto.DeleteResponse, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("Deleting data from IPFS by cid: %s", req.Cid)

	status := "ok"
	start := time.Now()
	defer func() {
		deleteDuration.WithLabelValues(status).Observe(time.Since(start).Seconds())
		deleteTotal.WithLabelValues(status).Inc()
	}()

	cid, err := cid.Decode(req.Cid)
	if err != nil {
		status = "err"
		logger.Warnf("failed to decode cid: %s", err)
		return nil, err
	}

	logger.Debugf("decoded cid: %s", cid.String())

	path := path.FromCid(cid)

	logger.Debugf("unpining path: %s", path.String())
	err = pi.node.Pin().Rm(ctx, path)
	if err != nil {
		status = "err"
		logger.Warnf("failed to unpin cid (%s): %s", path.String(), err)
		return nil, err
	}

	logger.Debugf("removing path from IPFS: %s", path.String())

	err = pi.node.Block().Rm(ctx, path)
	if err != nil {
		status = "err"
		logger.Warnf("failed to delete data: %s", err)
		return nil, err
	}

	logger.Debugf("removed path from cache: %b", pi.cache.Remove(path.String()))
	cacheItems.WithLabelValues("data").Set(float64(pi.cache.Len()))

	return &pluginsproto.DeleteResponse{
		Success: true,
	}, nil
}

func (pi *Plugin) resolveOrGenerateKey(ctx context.Context, name string) (iface.Key, error) {
	logger := utils.GetLogger("orbitport:ipfs")

	// if key exists, update the mutable link
	logger.Debugf("attmept to resolve key by name: %s", name)
	key, err := pi.keyForName(ctx, name)
	if err == nil {
		return key, nil
	}

	logger.Infof("name does not exist, creating new one: %s", name)
	key, err = pi.node.Key().Generate(ctx, name)
	if err != nil {
		logger.Warnf("failed to generate key: %s", err)
		return nil, err
	}

	return key, nil
}

// publish publishes the data on IPNS using the provided name.
// NOTE: assuming a key for the given name already exists
func (pi *Plugin) publish(ctx context.Context, p path.Path, name string) (*ipns.Name, error) {
	logger := utils.GetLogger("orbitport:ipfs")

	logger.Infof("Publishing on IPNS (%s): %s", name, p)

	published, err := pi.node.Name().Publish(ctx, p,
		options.Name.Key(name),
		options.Name.AllowOffline(true),
		options.Name.ValidTime(pi.leaseDuration),
	)

	if err != nil {
		logger.Warnf("failed to publish data: %s", err)
		return nil, err
	}

	pi.cachePublishedName(name, published, p)
	logger.Infof("published %s", published.AsPath())

	return &published, nil
}

func (pi *Plugin) cachePublishedName(alias string, published ipns.Name, p path.Path) {
	// Cache the latest head under every form callers may use:
	// local alias, bare peer ID, and canonical /ipns/<peerID>.
	_ = pi.ipnsCache.Add(alias, p)
	_ = pi.ipnsCache.Add(published.String(), p)
	_ = pi.ipnsCache.Add(published.AsPath().String(), p)
	cacheItems.WithLabelValues("ipns").Set(float64(pi.ipnsCache.Len()))
}

func (pi *Plugin) getByPath(ctx context.Context, path path.Path, namespace string) ([]byte, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("Getting data from IPFS for path: %s", path)

	// check cache first
	cachedData, ok := pi.cache.Get(path.String())
	if ok {
		source := "cache"
		status := "ok"
		cacheDataBytes := cachedData.([]byte)
		cacheHitsTotal.WithLabelValues("ipfs").Inc()
		getTotal.WithLabelValues(source, namespace, status).Inc()

		logger.Infof("data found in cache for path: %s. Data size: %d", path.String(), len(cacheDataBytes))
		return cacheDataBytes, nil
	}

	cacheMissesTotal.WithLabelValues("ipfs").Inc()

	source := "ipfs"
	// get the data
	reader, err := pi.node.Block().Get(ctx, path)
	if err != nil {
		status := "err"
		getTotal.WithLabelValues(source, namespace, status).Inc()

		logger.Warnf("failed to get data: %s", err)
		return nil, err
	}

	data, err := io.ReadAll(io.LimitReader(reader, int64(pi.maxGetBytes)+1))
	if err != nil {
		status := "err"
		getTotal.WithLabelValues(source, namespace, status).Inc()

		logger.Warnf("failed to read data: %s", err)
		return nil, err
	}

	if uint(len(data)) > pi.maxGetBytes {
		status := "err"
		getTotal.WithLabelValues(source, namespace, status).Inc()
		err := fmt.Errorf("get payload too large: %d bytes exceeds max %d", len(data), pi.maxGetBytes)
		logger.Warn(err.Error())
		return nil, err
	}

	logger.Debugf("read <%d> bytes for path: %s", len(data), path.String())

	return data, nil
}

func (pi *Plugin) keyForName(ctx context.Context, name string) (iface.Key, error) {
	logger := utils.GetLogger("orbitport:ipfs")

	// Prefer direct key lookup by alias instead of depending on key listing support.
	// Some IPFS deployments expose key generation and publishing but not key listing.
	key, _, err := pi.node.Key().Sign(ctx, name, []byte("orbitport-key-lookup"))
	if err == nil {
		return key, nil
	}
	logger.Debugf("direct key lookup via sign failed for %q: %s", name, err)

	keys, listErr := pi.node.Key().List(ctx)
	if listErr != nil {
		logger.Warnf("failed to list keys: %s", listErr)
		return nil, errors.Join(err, listErr)
	}

	for _, key := range keys {
		if key.Name() == name {
			return key, nil
		}
	}

	return nil, errors.New("key not found")
}

func convertToMultiaddr(httpAddr string) (string, error) {
	u, err := url.Parse(httpAddr)
	if err != nil {
		return "", err
	}

	host := u.Hostname()
	port := u.Port()

	if port == "" {
		port = "80" // default port for HTTP
		if u.Scheme == "https" {
			port = "443"
		}
	}

	return fmt.Sprintf("/dns/%s/tcp/%s/%s", host, port, u.Scheme), nil
}

func (pi *Plugin) KeyInfo(ctx context.Context, req *pluginsproto.KeyInfoRequest) (*pluginsproto.KeyInfoResponse, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("KeyInfo lookup for alias: %s", req.PublishName)

	key, err := pi.keyForName(ctx, req.PublishName)
	if err != nil {
		// Alias not found; return empty without error so callers can treat as "doesn't exist"
		logger.Warnf("KeyInfo(%s): key not found", req.PublishName)
		return &pluginsproto.KeyInfoResponse{IpnsName: ""}, nil
	}

	// ipnsName is "/ipns/<peerID>"
	ipnsName := key.Path().String()
	return &pluginsproto.KeyInfoResponse{IpnsName: ipnsName}, nil
}

// logErrorChain prints useful diagnostics for wrapped errors (HTTP status, unwrap chain).
func logErrorChain(logger interface {
	Warnf(format string, args ...any)
}, err error) {
	if err == nil {
		return
	}

	// Walk unwrap chain (prints wrapped HTTP/root-cause errors).
	unwrapped := err
	for depth := 0; depth < 10; depth++ {
		next := errors.Unwrap(unwrapped)
		if next == nil {
			break
		}
		logger.Warnf("  unwrap[%d]: type=%T err=%s", depth, next, next.Error())
		unwrapped = next
	}

	// If the error exposes a status code, print it (no internal imports).
	type hasStatus interface{ StatusCode() int }
	if se, ok := err.(hasStatus); ok {
		logger.Warnf("  statusCode=%d", se.StatusCode())
	}
}
