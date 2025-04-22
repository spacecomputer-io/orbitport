package ipfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"

	lru "github.com/hashicorp/golang-lru"
	"github.com/ipfs/boxo/path"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/kubo/client/rpc"
	iface "github.com/ipfs/kubo/core/coreiface"
	"github.com/ipfs/kubo/core/coreiface/options"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/spacecomputerio/orbitport/agents/pkg/utils"
	agentsproto "github.com/spacecomputerio/orbitport/agents/proto"
)

type Agent struct {
	agentsproto.IpfsAgentServiceServer

	node  *rpc.HttpApi
	cache *lru.Cache
}

// NewAgent creates a new IPFS agent with a storage layer.
func NewAgent() (*Agent, error) {
	cfg := readFromEnv()

	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("creating agent with config: %+v", cfg)

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

	logger.Info("IPFS agent created")

	cache, err := lru.New(cfg.CacheSize)
	if err != nil {
		logger.Warnf("failed to create cache: %s", err)
		return nil, err
	}

	return &Agent{
		node:  node,
		cache: cache,
	}, nil
}

// Add implements the Add RPC method.
func (a *Agent) Add(ctx context.Context, req *agentsproto.AddRequest) (*agentsproto.AddResponse, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Info("Adding data to IPFS")

	block, err := a.node.Block().Put(ctx, bytes.NewReader(req.Data))
	if err != nil {
		logger.Warnf("failed to add data: %s", err)
		return nil, err
	}

	var updatedIpnsName *string

	// if ipns name is provided, publish the newly created CID to this name
	if req.IpnsName != nil {
		resolved, err := a.node.Name().Resolve(ctx, *req.IpnsName)
		if err != nil {
			logger.Warnf("failed to resolve name: %s", err)
			return nil, err
		}

		// if key exists, update the mutable link
		if resolved != nil {
			logger.Infof("updating existing name: %s", req.IpnsName)
			key, err := a.keyForName(ctx, *req.IpnsName)
			if err != nil {
				logger.Errorf("failed to get key for name, but must exist: %s", err)
				return nil, err
			}

			logger.Debugf("publishing using key: %s", key.Name())

			// update the value for the existing name
			_, err = a.node.Name().Publish(ctx, block.Path(), options.Name.Key(key.Name()))
			if err != nil {
				logger.Warnf("failed to update name: %s", err)
				return nil, err
			}

			logger.Infof("updated name: %s", req.IpnsName)

			updatedIpnsName = req.IpnsName
		} else {
			logger.Infof("name does not exist, creating new one: %s", req.IpnsName)

			key, err := a.node.Key().Generate(ctx, *req.IpnsName)
			if err != nil {
				logger.Warnf("failed to generate key: %s", err)
				return nil, err
			}

			logger.Debugf("generated key: %s", key.Name())

			// publish the newly created key
			name, err := a.node.Name().Publish(ctx, block.Path(), options.Name.Key(key.Name()))
			if err != nil {
				logger.Warnf("failed to publish key: %s", err)
				return nil, err
			}

			logger.Infof("published name: %s", name)
		}
	}

	path := block.Path()

	logger.Infof("caching data for path: %s. Data size: %d", path.String(), len(req.Data))

	// add to cache
	a.cache.Add(path.String(), req.Data)

	return &agentsproto.AddResponse{
		Cid:      path.RootCid().String(),
		IpnsName: updatedIpnsName,
	}, nil
}

// Get implements the Get RPC method.
func (a *Agent) Get(ctx context.Context, req *agentsproto.GetRequest) (*agentsproto.GetResponse, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("Getting data from IPFS for key: %s. Namespace: %s", req.Key, req.Namespace)

	var p path.Path
	if req.Namespace == "ipns" {
		// resolve by name
		resolved, err := a.node.Name().Resolve(ctx, req.Key)
		if err != nil {
			logger.Warnf("failed to resolve name (does it exist?): %s", err)
			return nil, err
		}

		p = resolved
	} else {
		// resolve by cid
		cid, err := cid.Decode(req.Key)
		if err != nil {
			logger.Warnf("failed to decode cid: %s", err)
			return nil, err
		}

		p = path.FromCid(cid)
	}

	logger.Debugf("resolved path: %s", p.String())

	// get the data
	data, err := a.getByPath(ctx, p)
	if err != nil {
		logger.Warnf("failed to get data with path <%s>: %s", p.String(), err)
		return nil, err
	}

	return &agentsproto.GetResponse{
		Data: data,
	}, nil
}

// Delete implements the Delete RPC method.
func (a *Agent) Delete(ctx context.Context, req *agentsproto.DeleteRequest) (*agentsproto.DeleteResponse, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("Deleting data from IPFS by cid: %s", req.Cid)

	cid, err := cid.Decode(req.Cid)
	if err != nil {
		logger.Warnf("failed to decode cid: %s", err)
		return nil, err
	}

	logger.Debugf("decoded cid: %s", cid.String())

	path := path.FromCid(cid)

	logger.Debugf("path: %s", path.String())

	err = a.node.Block().Rm(ctx, path)
	if err != nil {
		logger.Warnf("failed to delete data: %s", err)
		return nil, err
	}

	logger.Debugf("removed path from cache: %b", a.cache.Remove(path.String()))

	return &agentsproto.DeleteResponse{
		Success: true,
	}, nil
}

func (a *Agent) getByPath(ctx context.Context, path path.Path) ([]byte, error) {
	logger := utils.GetLogger("orbitport:ipfs")
	logger.Infof("Getting data from IPFS for path: %s", path)

	// check cache first
	cachedData, ok := a.cache.Get(path.String())
	if ok {
		logger.Infof("data found in cache for path: %s. Data size: %d", path.String(), len(cachedData.([]byte)))
		return cachedData.([]byte), nil
	}

	// get the data
	reader, err := a.node.Block().Get(ctx, path)
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

func (a *Agent) keyForName(ctx context.Context, name string) (iface.Key, error) {
	logger := utils.GetLogger("orbitport:ipfs")

	keys, err := a.node.Key().List(ctx)
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
