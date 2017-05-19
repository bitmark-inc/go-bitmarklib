package bitmarklib

import (
	"bytes"
	"fmt"
	"github.com/bitmark-inc/bitmarkd/account"
	"github.com/bitmark-inc/bitmarkd/keypair"
	"github.com/bitmark-inc/bitmarkd/util"
	"golang.org/x/crypto/sha3"
)

const (
	variantPrivateKey = 0x00
	variantPublicKey  = 0x01

	variantLivenet = 0x00
	variantTestnet = 0x01

	variantKeyTypeED25519 = 0x01
)

const (
	seedLength        = 40
	kifChecksumLength = 4
)

type KeyType int

const (
	Nothing KeyType = iota
	ED25519 KeyType = iota
)

var (
	ErrKIFLength        = fmt.Errorf("kif length is invalid")
	ErrInvalidSeed      = fmt.Errorf("invalid seed")
	ErrInvalidKeyType   = fmt.Errorf("invalid key type")
	ErrInvalidAlgorithm = fmt.Errorf("invalid key algorithm")
	ErrChecksumMismatch = fmt.Errorf("checksum mismatch")
)

type KeyPair struct {
	*account.PrivateKey
	Seed string
}

// Return a KIF string for a keypair
func (kp KeyPair) KIF() (string, error) {

	if kp.Seed == "" {
		return "", ErrInvalidSeed
	}

	isTest := kp.PrivateKey.IsTesting()

	var variant uint64 = variantKeyTypeED25519 << 4

	if isTest {
		variant |= variantTestnet << 1
	}

	seedBytes := util.FromBase58(kp.Seed)

	b := append(util.ToVarint64(variant), seedBytes...)
	checksum := sha3.Sum256(b)
	kifBytes := append(b, checksum[:4]...)

	return util.ToBase58(kifBytes), nil
}

// NewKeyPair will first generate a seed. Then it use the seed
// to generate a new keypair
func NewKeyPair(test bool, algorithm KeyType) (*KeyPair, error) {
	seed, err := keypair.NewSeed(test)
	if err != nil {
		return nil, err
	}

	return NewKeyPairFromBase58Seed(seed)
}

// Generate a new keypair with specific seed string.
// The the network info and the algorithm will be
// extracted from in the seed.
func NewKeyPairFromBase58Seed(seed string) (*KeyPair, error) {
	p, err := account.PrivateKeyFromBase58Seed(seed)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: p,
		Seed:       seed,
	}, nil
}

// Generate keypair from base58 private key. The keypair may be lack of
// network info and algorithm.
func NewKeyPairFromBase58PrivateKey(key string, algorithm KeyType) *KeyPair {
	keyBytes := util.FromBase58(key)
	var p *account.PrivateKey

	switch algorithm {
	case ED25519:
		p = &account.PrivateKey{
			PrivateKeyInterface: &account.ED25519PrivateKey{
				PrivateKey: keyBytes,
			},
		}
	default:
	}

	return &KeyPair{
		PrivateKey: p,
	}
}

// Generate a new keypair from a KIF string
func NewKeyPairFromKIF(kif string) (*KeyPair, error) {
	b := util.FromBase58(kif)
	v, n := util.FromVarint64(b)

	if n+seedLength+kifChecksumLength != len(b) {
		return nil, ErrKIFLength
	}

	if v&0x01 != variantPrivateKey {
		return nil, ErrInvalidKeyType
	}

	v = v >> 4
	switch v & 0x01 {
	case variantKeyTypeED25519:
	default:
		return nil, ErrInvalidAlgorithm
	}

	seedBytes := b[n : n+seedLength]
	kifChecksum := b[n+seedLength:]

	checksum := sha3.Sum256(b[:n+seedLength])
	if !bytes.Equal(checksum[:kifChecksumLength], kifChecksum) {
		return nil, ErrChecksumMismatch
	}
	seed := util.ToBase58(seedBytes)

	p, err := account.PrivateKeyFromBase58Seed(seed)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: p,
		Seed:       seed,
	}, nil
}
