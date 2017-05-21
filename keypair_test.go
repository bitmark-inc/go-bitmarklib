package bitmarklib

import (
	"bytes"
	"github.com/bitmark-inc/bitmarkd/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFromKIF(t *testing.T) {
	kif := "TLpSduNW7r3zrkc9foneYs2zTkikVPnY1SNZaYbispusdFmittczPGKDLKtzH"
	kp, err := NewKeyPairFromKIF(kif)
	assert.NoError(t, err)
	assert.True(t, kp.PrivateKey.IsTesting())
	privateKey := util.ToBase58(kp.PrivateKey.PrivateKeyBytes())
	assert.Equal(t, privateKey,
		"5xJrqMvvHixJ8SVJyXgQDPiW46Ghbxkk6EkqGRqRnj7FUh5bsKPi2vejjGkTaM5ed24Q14bW4sx2ce38HVD16Jx8",
	)
}

func TestNetworkTypeTestnet(t *testing.T) {
	seed := "5XEECseCzmTE1SeJb5tQCpDK6cyDx2qKinCg5BNFgWnn3d9FjsEVDHZ"

	kp, err := NewKeyPairFromBase58Seed(seed)
	assert.NoError(t, err)
	assert.Equal(t, "testnet", kp.Network())
}

func TestNetworkTypeLivenet(t *testing.T) {
	seed := "5XEECqgoxCaQyGgJBMtW2WP57bnu4eVUUveNN56RZan5NuwuhDW6Mvw"

	kp, err := NewKeyPairFromBase58Seed(seed)
	assert.NoError(t, err)
	assert.Equal(t, "livenet", kp.Network())
}

func TestKIFEncodeDecode(t *testing.T) {
	p1, err := NewKeyPair(true, ED25519)
	assert.NoError(t, err)

	kif, err := p1.KIF()
	assert.NoError(t, err)

	p2, err := NewKeyPairFromKIF(kif)
	assert.NoError(t, err)

	assert.True(t, bytes.Equal(
		p1.PrivateKey.PrivateKeyBytes(),
		p2.PrivateKey.PrivateKeyBytes()))
}
