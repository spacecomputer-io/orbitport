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

	"github.com/spacecomputerio/orbitport/plugins/pkg/utils"
	pluginsproto "github.com/spacecomputerio/orbitport/plugins/proto"
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

	return &Plugin{
		node:          node,
		cache:         cache,
		ipnsCache:     ipnsCache,
		leaseDuration: cfg.LeaseDuration,
	}, nil
}

// Add implements the Add RPC method.
func (pi *Plugin) Add(ctx context.Context, req *pluginsproto.AddRequest) (*pluginsproto.AddResponse, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Info("Adding data to IPFS")

	block, err := pi.node.Block().Put(ctx, bytes.NewReader(req.Data))
	if err != nil {
		logger.Warnf("failed to add data: %s", err)
		return nil, err
	}
	// pin the added block
	if err := pi.node.Pin().Add(ctx, block.Path()); err != nil {
		logger.Warnf("failed to pin cid (%s): %s", block.Path().RootCid(), err)
		return nil, err
	}

	var ipnsName string

	// publish on IPNS if a name is provided
	publishName := req.PublishName
	if publishName != nil && len(*publishName) > 0 {
		name := *publishName
		_, err := pi.resolveOrGenerateKey(ctx, name)
		if err != nil {
			return nil, err
		}
		if updatedName, err := pi.publish(ctx, block.Path(), name); err != nil {
			logger.Warnf("failed to publish (%s): %s", name, err)
			return nil, err
		} else {
			ipnsName = updatedName.String()
		}
	}

	path := block.Path()

	logger.Debugf("caching data for path: %s. Data size: %d", path.String(), len(req.Data))
	// add to cache
	pi.cache.Add(path.String(), req.Data)

	resp := &pluginsproto.AddResponse{
		Cid: path.RootCid().String(),
	}
	if len(ipnsName) > 0 {
		resp.IpnsName = &ipnsName
	}
	return resp, nil
}

// Get implements the Get RPC method.
func (pi *Plugin) Get(ctx context.Context, req *pluginsproto.GetRequest) (*pluginsproto.GetResponse, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("Getting data from IPFS for key: %s. Namespace: %s", req.Key, req.Namespace)

	var p path.Path
	switch req.Namespace {
	case "ipfs":
		// resolve by cid
		cid, err := cid.Decode(req.Key)
		if err != nil {
			logger.Warnf("failed to decode cid (%s): %s", req.Key, err)
			return nil, err
		}
		p = path.FromCid(cid)
	case "ipns": // resolve by name
		name := req.Key
		// check if the name is in the cache
		if resolved, ok := pi.ipnsCache.Get(name); ok {
			logger.Debugf("found in cache: %s", name)
			p = resolved.(path.Path)
		} else {
			// resolve by name
			resolved, err := pi.node.Name().Resolve(ctx, name)
			if err != nil {
				logger.Warnf("failed to resolve name (does it exist?): %s", err)
				return nil, err
			}
			p = resolved

			pi.ipnsCache.Add(name, p)
			logger.Debugf("resolved path for name: %s", name)
		}
	default:
		logger.Warnf("unknown namespace: %s", req.Namespace)
		return nil, fmt.Errorf("unknown namespace: %s", req.Namespace)
	}
	logger.Debugf("resolved path: %s", p.String())

	// get the data
	data, err := pi.getByPath(ctx, p)
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

	key, err := pi.resolveOrGenerateKey(ctx, req.PublishName)
	if err != nil {
		return nil, err
	}
	cid, err := cid.Decode(req.Cid)
	if err != nil {
		logger.Warnf("failed to decode cid (%s): %s", req.Cid, err)
		return nil, err
	}
	updatedName, err := pi.publish(ctx, path.FromCid(cid), key.Name())
	if err != nil {
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

	cid, err := cid.Decode(req.Cid)
	if err != nil {
		logger.Warnf("failed to decode cid: %s", err)
		return nil, err
	}

	logger.Debugf("decoded cid: %s", cid.String())

	path := path.FromCid(cid)

	logger.Debugf("unpining path: %s", path.String())
	err = pi.node.Pin().Rm(ctx, path)
	if err != nil {
		logger.Warnf("failed to unpin cid (%s): %s", path.String(), err)
		return nil, err
	}
	logger.Debugf("removing path from IPFS: %s", path.String())

	err = pi.node.Block().Rm(ctx, path)
	if err != nil {
		logger.Warnf("failed to delete data: %s", err)
		return nil, err
	}

	logger.Debugf("removed path from cache: %b", pi.cache.Remove(path.String()))

	return &pluginsproto.DeleteResponse{
		Success: true,
	}, nil
}

func (pi *Plugin) resolveOrGenerateKey(ctx context.Context, name string) (iface.Key, error) {
	logger := utils.GetLogger("orbitport:ipfs")

	resolved, _ := pi.node.Name().Resolve(ctx, name)
	// if key exists, update the mutable link
	if resolved != nil {
		logger.Infof("updating existing name: %s", name)
		key, err := pi.keyForName(ctx, name)
		if err != nil {
			logger.Warnf("failed to get key for name: %s", err)
			return nil, err
		}
		return key, nil
	}

	logger.Infof("name does not exist, creating new one: %s", name)
	key, err := pi.node.Key().Generate(ctx, name)
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

	// cache the published name
	_ = pi.ipnsCache.Add(name, p)
	logger.Infof("published %s", published.AsPath())

	return &published, nil
}

func (pi *Plugin) getByPath(ctx context.Context, path path.Path) ([]byte, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("Getting data from IPFS for path: %s", path)

	// check cache first
	cachedData, ok := pi.cache.Get(path.String())
	if ok {
		logger.Infof("data found in cache for path: %s. Data size: %d", path.String(), len(cachedData.([]byte)))
		return cachedData.([]byte), nil
	}

	// get the data
	reader, err := pi.node.Block().Get(ctx, path)
	if err != nil {
		logger.Warnf("failed to get data: %s", err)
		return nil, err
	}

	data, err := io.ReadAll(reader)
	if err != nil {
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
