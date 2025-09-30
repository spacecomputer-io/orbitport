package ipfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
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

	addBytes.Observe(float64(len(req.Data)))

	t := time.Now()
	block, err := pi.node.Block().Put(ctx, bytes.NewReader(req.Data))
	rpc := "block_put"
	if err != nil {
		rpcTotal.WithLabelValues(rpc, "err").Inc()
		rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())
		status = "err"
		logger.Warnf("failed to add data: %s", err)
		return nil, err
	}

	rpcTotal.WithLabelValues(rpc, "ok").Inc()
	rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())

	// pin the added block
	t = time.Now()
	if err := pi.node.Pin().Add(ctx, block.Path()); err != nil {
		rpcTotal.WithLabelValues("pin_add", "err").Inc()
		rpcDuration.WithLabelValues("pin_add").Observe(time.Since(t).Seconds())
		status = "err"
		logger.Warnf("failed to pin cid (%s): %s", block.Path().RootCid(), err)
		return nil, err
	}

	rpcTotal.WithLabelValues("pin_add", "ok").Inc()
	rpcDuration.WithLabelValues("pin_add").Observe(time.Since(t).Seconds())

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
	case "ipns": // resolve by name
		name := req.Key
		// check if the name is in the cache
		if resolved, ok := pi.ipnsCache.Get(name); ok {
			cacheHitsTotal.WithLabelValues("ipns").Inc()
			logger.Debugf("found in cache: %s", name)
			p = resolved.(path.Path)
		} else {
			cacheMissesTotal.WithLabelValues("ipns").Inc()
			t := time.Now()
			// resolve by name
			resolved, err := pi.node.Name().Resolve(ctx, name)
			rpc := "name_resolve"
			if err != nil {
				rpcTotal.WithLabelValues(rpc, "err").Inc()
				rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())
				status = "err"
				getTotal.WithLabelValues(source, req.Namespace, status).Inc()
				logger.Warnf("failed to resolve name (does it exist?): %s", err)
				return nil, err
			}
			rpcTotal.WithLabelValues(rpc, "ok").Inc()
			rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())

			p = resolved

			pi.ipnsCache.Add(name, p)
			cacheItems.WithLabelValues("ipns").Set(float64(pi.ipnsCache.Len()))
			logger.Debugf("resolved path for name: %s", name)
		}
	default:
		status = "err"
		getTotal.WithLabelValues(source, req.Namespace, status).Inc()
		logger.Warnf("unknown namespace: %s", req.Namespace)
		return nil, fmt.Errorf("unknown namespace: %s", req.Namespace)
	}
	logger.Debugf("resolved path: %s", p.String())

	// get the data
	data, err := pi.getByPath(ctx, p, req.Namespace)
	if err != nil {
		logger.Warnf("failed to get data with path <%s>: %s", p.String(), err)
		return nil, err
	}

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

	t := time.Now()
	key, err := pi.resolveOrGenerateKey(ctx, req.PublishName)
	rpc := "key_list"
	rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())
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

	t = time.Now()
	updatedName, err := pi.publish(ctx, path.FromCid(cid), key.Name())
	rpc = "name_publish"
	rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())
	if err != nil {
		rpcTotal.WithLabelValues(rpc, "err").Inc()
		status = "err"

		logger.Warnf("failed to publish (%s): %s", key.Name(), err)
		return nil, err
	}
	rpcTotal.WithLabelValues(rpc, "ok").Inc()
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
	t := time.Now()
	err = pi.node.Pin().Rm(ctx, path)
	if err != nil {
		rpcTotal.WithLabelValues("pin_rm", "err").Inc()
		rpcDuration.WithLabelValues("pin_rm").Observe(time.Since(t).Seconds())
		status = "err"
		logger.Warnf("failed to unpin cid (%s): %s", path.String(), err)
		return nil, err
	}
	rpcTotal.WithLabelValues("pin_rm", "ok").Inc()
	rpcDuration.WithLabelValues("pin_rm").Observe(time.Since(t).Seconds())

	logger.Debugf("removing path from IPFS: %s", path.String())

	t = time.Now()
	err = pi.node.Block().Rm(ctx, path)
	if err != nil {
		rpcTotal.WithLabelValues("block_rm", "err").Inc()
		rpcDuration.WithLabelValues("block_rm").Observe(time.Since(t).Seconds())
		status = "err"
		logger.Warnf("failed to delete data: %s", err)
		return nil, err
	}
	rpcTotal.WithLabelValues("block_rm", "ok").Inc()
	rpcDuration.WithLabelValues("block_rm").Observe(time.Since(t).Seconds())

	logger.Debugf("removed path from cache: %b", pi.cache.Remove(path.String()))
	cacheItems.WithLabelValues("data").Set(float64(pi.cache.Len()))

	return &pluginsproto.DeleteResponse{
		Success: true,
	}, nil
}

func (pi *Plugin) resolveOrGenerateKey(ctx context.Context, name string) (iface.Key, error) {
	logger := utils.GetLogger("orbitport:ipfs")

	// if key exists, update the mutable link
	t := time.Now()
	logger.Debugf("attmept to resolve key by name: %s", name)
	key, err := pi.keyForName(ctx, name)
	rpc := "key_list"
	if err == nil {
		rpcTotal.WithLabelValues(rpc, "err").Inc()
		rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())
		return key, nil
	}
	rpcTotal.WithLabelValues(rpc, "ok").Inc()
	rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())

	logger.Infof("name does not exist, creating new one: %s", name)
	t = time.Now()
	key, err = pi.node.Key().Generate(ctx, name)
	rpc = "key_generate"
	if err != nil {
		rpcTotal.WithLabelValues(rpc, "err").Inc()
		rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())
		logger.Warnf("failed to generate key: %s", err)
		return nil, err
	}

	rpcTotal.WithLabelValues(rpc, "ok").Inc()
	rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())

	return key, nil
}

// publish publishes the data on IPNS using the provided name.
// NOTE: assuming a key for the given name already exists
func (pi *Plugin) publish(ctx context.Context, p path.Path, name string) (*ipns.Name, error) {
	logger := utils.GetLogger("orbitport:ipfs")

	logger.Infof("Publishing on IPNS (%s): %s", name, p)

	t := time.Now()
	published, err := pi.node.Name().Publish(ctx, p,
		options.Name.Key(name),
		options.Name.AllowOffline(true),
		options.Name.ValidTime(pi.leaseDuration),
	)
	rpc := "name_publish"
	if err != nil {
		rpcTotal.WithLabelValues(rpc, "err").Inc()
		rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())
		logger.Warnf("failed to publish data: %s", err)
		return nil, err
	}
	rpcTotal.WithLabelValues(rpc, "ok").Inc()
	rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())

	// cache the published name
	_ = pi.ipnsCache.Add(name, p)
	cacheItems.WithLabelValues("ipns").Set(float64(pi.ipnsCache.Len()))
	logger.Infof("published %s", published.AsPath())

	return &published, nil
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
		getBytes.WithLabelValues(source, namespace).Observe(float64(len(cacheDataBytes)))
		cacheHitsTotal.WithLabelValues("ipfs").Inc()
		getTotal.WithLabelValues(source, namespace, status).Inc()

		logger.Infof("data found in cache for path: %s. Data size: %d", path.String(), len(cacheDataBytes))
		return cacheDataBytes, nil
	}

	cacheMissesTotal.WithLabelValues("ipfs").Inc()

	source := "ipfs"
	t := time.Now()
	// get the data
	reader, err := pi.node.Block().Get(ctx, path)
	rpc := "block_get"
	if err != nil {
		rpcTotal.WithLabelValues(rpc, "err").Inc()
		rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())
		status := "err"
		getTotal.WithLabelValues(source, namespace, status).Inc()

		logger.Warnf("failed to get data: %s", err)
		return nil, err
	}
	rpcTotal.WithLabelValues(rpc, "ok").Inc()
	rpcDuration.WithLabelValues(rpc).Observe(time.Since(t).Seconds())

	data, err := io.ReadAll(reader)
	if err != nil {
		status := "err"
		getTotal.WithLabelValues(source, namespace, status).Inc()

		logger.Warnf("failed to read data: %s", err)
		return nil, err
	}

	logger.Debugf("read <%d> bytes for path: %s", len(data), path.String())

	return data, nil
}

func (pi *Plugin) keyForName(ctx context.Context, name string) (iface.Key, error) {
	logger := utils.GetLogger("orbitport:ipfs")

	keys, err := pi.node.Key().List(ctx)
	if err != nil {
		logger.Warnf("failed to list keys: %s", err)
		return nil, err
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

	return fmt.Sprintf("/dns/%s/tcp/%s", host, port), nil
}
