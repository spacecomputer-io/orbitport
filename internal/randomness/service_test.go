package randomness

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/spacecoinxyz/orbitport/internal/config"
	"github.com/spacecoinxyz/orbitport/internal/testutils"
	"github.com/spacecoinxyz/orbitport/internal/utils"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	randomness_common "github.com/spacecoinxyz/orbitport/internal/randomness/common"
)

func NewRandomnessServiceSuite() *RandomnessServiceSuite {
	rss := new(RandomnessServiceSuite)

	rss.threadControl = utils.NewThreadControl()

	return rss
}

type RandomnessServiceSuite struct {
	suite.Suite

	threadControl utils.ThreadControl
	cfg           config.Config
}

func (s *RandomnessServiceSuite) SetupSuite() {
	mockAptosAuth := testutils.NewMockServer(true, `{"access_token": "11111111111111", "expires_in": 3600, "token_type": "Bearer"}`)
	mockAptosApi := testutils.NewMockServer(true, `[{"chunk": "aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa", "signature": "aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa"}]`)

	authPort := 3050
	apiPort := 3051

	go mockAptosAuth.ListenAndServe(fmt.Sprintf(":%d", authPort))
	go mockAptosApi.ListenAndServe(fmt.Sprintf(":%d", apiPort))

	s.cfg = config.Config{
		AptosOrbitalAuthUrl:      "http://localhost:3050",
		AptosOrbitalApiUrl:       "http://localhost:3051",
		AptosOrbitalClientId:     "client_id",
		AptosOrbitalClientSecret: "client_secret",
		AptosOrbitalRateLimit:    1,
		MasterSeedInterval:       10 * time.Millisecond,
	}
}

func TestSuite(t *testing.T) {
	suite.Run(t, NewRandomnessServiceSuite())
}

func (s *RandomnessServiceSuite) TestSources() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	randService, err := New(s.cfg)
	require.NoError(s.T(), err)

	require.NoError(s.T(), randService.Start(ctx))
	defer randService.Close()

	s.Run("aptos", func() {
		seed, err := randService.GetRandomSeed(ctx, randomness_common.RandSourceAptosOrbital)
		require.NoError(s.T(), err)
		require.Equal(s.T(), seed.Src, randomness_common.RandSourceAptosOrbital)
	})

	s.Run("error: local cached - no master seed", func() {
		randService.(*randomnessService).masterSeed.Set(nil)
		_, err := randService.GetRandomSeed(ctx, randomness_common.RandSourceLocalDrivedFromSpaceSeed)
		require.ErrorIs(s.T(), err, ErrNoMasterSeedSet)
	})

	s.Run("local cached", func() {
		// let the master seed routine run the first time
		<-time.After(s.cfg.MasterSeedInterval)

		seed, err := randService.GetRandomSeed(ctx, randomness_common.RandSourceLocalDrivedFromSpaceSeed)
		require.NoError(s.T(), err)
		require.Equal(s.T(), seed.Src, randomness_common.RandSourceLocalDrivedFromSpaceSeed)
		require.Equal(s.T(), seed.Value, "aaa2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa")
		require.Equal(s.T(), seed.Sig, "aaa6022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890022100a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567aaa")
	})

	s.Run("local go_crypto", func() {
		seed, err := randService.GetRandomSeed(ctx, randomness_common.RandSourceLocalGoCrypto)
		require.NoError(s.T(), err)
		require.Equal(s.T(), seed.Src, randomness_common.RandSourceLocalGoCrypto)
	})

}
