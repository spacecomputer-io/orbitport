package gateway_api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/spacecoinxyz/orbitport/internal/config"
	"github.com/spacecoinxyz/orbitport/internal/randomness"
	randomness_common "github.com/spacecoinxyz/orbitport/internal/randomness/common"
	"github.com/spacecoinxyz/orbitport/internal/randomness/providers/aptosorbital"
	"github.com/spacecoinxyz/orbitport/internal/testutils"
	"github.com/spacecoinxyz/orbitport/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestRouter(t *testing.T) {
	//// in case of error, uncomment the following line to see logs
	require.NoError(t, utils.SetLogLevel("orbitport:*", "debug"))

	aptosAuthResp := `{"access_token": "11111111111111", "expires_in": 3600, "token_type": "Bearer"}`
	mockAptosAuth := testutils.NewMockServer(true, aptosAuthResp)
	go mockAptosAuth.ListenAndServe(":3050")
	aptosApiResp := `[{"chunk": "aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", "signature": "aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa"}]`
	mockAptosApi := testutils.NewMockServer(true, aptosApiResp)
	go mockAptosApi.ListenAndServe(":3051")

	staticAuthToken := "static_auth_token"

	cfg := config.Config{
		AptosOrbitalAuthUrl:      "http://localhost:3050",
		AptosOrbitalApiUrl:       "http://localhost:3051",
		AptosOrbitalClientId:     "client_id",
		AptosOrbitalClientSecret: "client_secret",
		AptosOrbitalRateLimit:    1,
		StaticAuthToken:          staticAuthToken,
	}
	randService, err := randomness.New(cfg)
	require.NoError(t, err)

	router, err := NewRouter(cfg, Services{
		Randomness: randService,
	})
	require.NoError(t, err)

	go func() {
		require.NoError(t, router.Run(":8088"))
	}()

	<-time.After(1 * time.Second) // TODO: avoid timeout

	baseURL := "http://localhost:8088"

	t.Run("bad token", func(t *testing.T) {
		_, err := queryRandSeed(baseURL, "badToken")
		require.Error(t, err)
	})

	t.Run("happy path", func(t *testing.T) {
		seed, err := queryRandSeed(baseURL, staticAuthToken)
		require.NoError(t, err)
		require.Equal(t, "aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", seed.Value)
		require.Equal(t, "aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", seed.Sig)
		require.Equal(t, seed.Src, aptosorbital.RandSeedSrc)
	})
}

func queryRandSeed(baseURL, token string) (*randomness_common.RandomSeed, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/rand_seed", baseURL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Bad status code: %d", resp.StatusCode)
	}

	respContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var randSeed randomness_common.RandomSeed
	err = json.Unmarshal(respContent, &randSeed)
	if err != nil {
		return nil, err
	}
	return &randSeed, nil
}
