package ipfs

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/testutils"
	"github.com/spacecomputer-io/orbitport/plugins/proto"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestIpfsPlugin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	apiPort, err := testutils.FreePort("tcp", 50000, 50100)
	require.NoError(t, err)
	ipfsNode, err := createIpfsNode(ctx, apiPort)
	require.NoError(t, err, "failed to get test container")
	defer func() {
		err := ipfsNode.Terminate(ctx)
		if err != nil {
			t.Fatalf("failed to terminate test container: %v", err)
		}
	}()
	t.Logf("IPFS node started: %s", ipfsNode.GetContainerID())
	// time.Sleep(56 * time.Second) // wait for IPFS to start
	plugin, err := createPlugin(apiPort)
	require.NoError(t, err, "failed to create plugin")

	t.Run("AddGetDelete", func(t *testing.T) {
		require.NoError(t, err, "failed to create plugin")
		now := time.Now()
		data := []byte(fmt.Sprintf("test data %d", now.UnixNano()))
		req := &proto.AddRequest{
			Data: data,
		}

		resp, err := plugin.Add(ctx, req)
		require.NoError(t, err, "failed to add data to IPFS")
		require.NotEmpty(t, resp.Cid, "CID should not be empty")

		t.Logf("data added to IPFS: %s", resp.Cid)
		// Verify data is retrievable
		getReq := &proto.GetRequest{
			Key:       resp.Cid,
			Namespace: "ipfs",
		}
		getResp, err := plugin.Get(ctx, getReq)
		require.NoError(t, err, "failed to get data from IPFS")
		require.Equal(t, data, getResp.Data, "retrieved data should match the original")
		require.Equal(t, resp.Cid, getReq.Key, "CID should match the key in GetResponse")
		t.Logf("data retrieved from IPFS: %s", getResp.Data)

		deleteReq := &proto.DeleteRequest{
			Cid: resp.Cid,
		}
		deleteResp, err := plugin.Delete(ctx, deleteReq)
		require.NoError(t, err, "failed to delete data from IPFS")
		require.True(t, deleteResp.Success, "delete operation should be successful")

		// Verify data is no longer retrievable
		_, err = plugin.Get(ctx, getReq)
		require.Error(t, err, "data should not be retrievable after deletion")
	})

	t.Run("Publish", func(t *testing.T) {
		now := time.Now()
		data := []byte(fmt.Sprintf("test data to be pubilshed %d", now.UnixNano()))
		publishName := fmt.Sprintf("test-publish-name-%d", now.Unix())
		req := &proto.AddRequest{
			Data: data,
		}

		resp, err := plugin.Add(ctx, req)
		require.NoError(t, err, "failed to add data to IPFS")

		pubresp, err := plugin.Publish(ctx, &proto.PublishRequest{
			Cid:         resp.Cid,
			PublishName: publishName,
		})
		require.NoError(t, err, "failed to publish data to IPNS")
		fmt.Printf("got response: %v\n", resp)
		require.NotEmpty(t, resp.Cid, "CID should not be empty")
		require.NotNil(t, pubresp.IpnsName, "IPNS name should not be nil")
		require.NotEmpty(t, pubresp.IpnsName, "IPNS name should not be empty")
		t.Logf("data added to IPFS: %s", resp.Cid)
		t.Logf("IPNS name: %s", pubresp.IpnsName)

		// Verify data is retrievable via IPNS
		getReq := &proto.GetRequest{
			Key:       pubresp.IpnsName,
			Namespace: "ipns",
		}
		getResp, err := plugin.Get(ctx, getReq)
		require.NoError(t, err, "failed to get data from IPFS via IPNS")
		require.Equal(t, data, getResp.Data, "retrieved data should match the original")
		t.Logf("data retrieved from IPFS via IPNS: %s", getResp.Path)
	})

	t.Run("AddRejectsOversizedPayload", func(t *testing.T) {
		pluginWithSmallAddLimit, err := createPluginWithLimits(apiPort, 16, 1048576)
		require.NoError(t, err, "failed to create plugin with small add limit")

		_, err = pluginWithSmallAddLimit.Add(ctx, &proto.AddRequest{
			Data: []byte("this payload is definitely larger than sixteen bytes"),
		})
		require.Error(t, err, "expected oversized add payload to be rejected")
		require.Contains(t, err.Error(), "add payload too large")
	})

	t.Run("GetRejectsOversizedPayload", func(t *testing.T) {
		pluginWithDefaultLimits, err := createPluginWithLimits(apiPort, 1048576, 1048576)
		require.NoError(t, err, "failed to create plugin with default limits")

		addResp, err := pluginWithDefaultLimits.Add(ctx, &proto.AddRequest{
			Data: []byte("this payload is larger than sixteen bytes"),
		})
		require.NoError(t, err, "failed to add data for oversized get test")

		pluginWithSmallGetLimit, err := createPluginWithLimits(apiPort, 1048576, 16)
		require.NoError(t, err, "failed to create plugin with small get limit")

		_, err = pluginWithSmallGetLimit.Get(ctx, &proto.GetRequest{
			Key:       addResp.Cid,
			Namespace: "ipfs",
		})
		require.Error(t, err, "expected oversized get payload to be rejected")
		require.Contains(t, err.Error(), "get payload too large")
	})
}

func createIpfsNode(ctx context.Context, apiPort uint16) (testcontainers.Container, error) {
	req := testcontainers.ContainerRequest{
		Image:           "ipfs/kubo:release",
		Name:            "ipfs-node",
		HostAccessPorts: []int{5001},
		ExposedPorts:    []string{"5001/tcp"},
		HostConfigModifier: func(h *container.HostConfig) {
			h.PortBindings = map[nat.Port][]nat.PortBinding{
				nat.Port("5001/tcp"): {
					{
						HostPort: fmt.Sprintf("%d", apiPort),
					},
				},
			}
		},
		WaitingFor: wait.ForLog("Daemon is ready"),
		Cmd:        []string{"daemon", "--migrate=true", "--offline"},
	}

	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

func createPlugin(ipfsApiPort uint16) (*Plugin, error) {
	return createPluginWithLimits(ipfsApiPort, 1048576, 1048576)
}

func createPluginWithLimits(ipfsApiPort uint16, maxAddBytes, maxGetBytes uint) (*Plugin, error) {
	viper.Set("IPFS_ADDRESS", fmt.Sprintf("http://localhost:%d", ipfsApiPort))
	viper.Set("PLUGIN_MAX_ADD_BYTES", maxAddBytes)
	viper.Set("PLUGIN_MAX_GET_BYTES", maxGetBytes)
	plugin, err := NewPlugin()
	if err != nil {
		return nil, err
	}
	return plugin, nil
}
