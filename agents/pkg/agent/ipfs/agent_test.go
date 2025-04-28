package ipfs

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/spacecomputerio/orbitport/agents/pkg/testutils"
	"github.com/spacecomputerio/orbitport/agents/proto"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestIpfsAgent(t *testing.T) {
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
	agent, err := createAgent(apiPort)
	require.NoError(t, err, "failed to create agent")

	t.Run("AddGetDelete", func(t *testing.T) {
		require.NoError(t, err, "failed to create agent")
		now := time.Now()
		data := []byte(fmt.Sprintf("test data %d", now.UnixNano()))
		req := &proto.AddRequest{
			Data: data,
		}

		resp, err := agent.Add(ctx, req)
		require.NoError(t, err, "failed to add data to IPFS")
		require.NotEmpty(t, resp.Cid, "CID should not be empty")

		t.Logf("data added to IPFS: %s", resp.Cid)
		// Verify data is retrievable
		getReq := &proto.GetRequest{
			Key:       resp.Cid,
			Namespace: "ipfs",
		}
		getResp, err := agent.Get(ctx, getReq)
		require.NoError(t, err, "failed to get data from IPFS")
		require.Equal(t, data, getResp.Data, "retrieved data should match the original")
		require.Equal(t, resp.Cid, getReq.Key, "CID should match the key in GetResponse")
		t.Logf("data retrieved from IPFS: %s", getResp.Data)

		deleteReq := &proto.DeleteRequest{
			Cid: resp.Cid,
		}
		deleteResp, err := agent.Delete(ctx, deleteReq)
		require.NoError(t, err, "failed to delete data from IPFS")
		require.True(t, deleteResp.Success, "delete operation should be successful")

		// Verify data is no longer retrievable
		_, err = agent.Get(ctx, getReq)
		require.Error(t, err, "data should not be retrievable after deletion")
	})

	t.Run("Publish", func(t *testing.T) {
		now := time.Now()
		data := []byte(fmt.Sprintf("test data to be pubilshed %d", now.UnixNano()))
		publishName := fmt.Sprintf("test-publish-name-%d", now.Unix())
		req := &proto.AddRequest{
			Data:        data,
			PublishName: &publishName,
		}

		resp, err := agent.Add(ctx, req)
		require.NoError(t, err, "failed to add data to IPFS")
		fmt.Printf("got response: %v\n", resp)
		require.NotEmpty(t, resp.Cid, "CID should not be empty")
		require.NotNil(t, resp.IpnsName, "IPNS name should not be nil")
		require.NotEmpty(t, *resp.IpnsName, "IPNS name should not be empty")
		t.Logf("data added to IPFS: %s", resp.Cid)
		t.Logf("IPNS name: %s", *resp.IpnsName)

		// Verify data is retrievable via IPNS
		getReq := &proto.GetRequest{
			Key:       *resp.IpnsName,
			Namespace: "ipns",
		}
		getResp, err := agent.Get(ctx, getReq)
		require.NoError(t, err, "failed to get data from IPFS via IPNS")
		require.Equal(t, data, getResp.Data, "retrieved data should match the original")
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

func createAgent(ipfsApiPort uint16) (*Agent, error) {
	viper.Set("IPFS_ADDRESS", fmt.Sprintf("http://localhost:%d", ipfsApiPort))
	agent, err := NewAgent()
	if err != nil {
		return nil, err
	}
	return agent, nil
}
