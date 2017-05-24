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

// The algorithm type of a keypair
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

// Keypair is the most important part of bitmark. Every action requires
// a signature which is signed from a keypair.
type KeyPair struct {
	*account.PrivateKey
	seed []byte
}

// KIF returns a KIF string for a keypair
func (kp KeyPair) KIF() (string, error) {

	if kp.seed == nil {
		return "", ErrInvalidSeed
	}

	isTest := kp.PrivateKey.IsTesting()

	var variant uint64 = variantKeyTypeED25519 << 4

	if isTest {
		variant |= variantTestnet << 1
	}

	b := append(util.ToVarint64(variant), kp.seed...)
	checksum := sha3.Sum256(b)
	kifBytes := append(b, checksum[:4]...)

	return util.ToBase58(kifBytes), nil
}

// Seed returns the base58 string of a seed of a keypair
func (kp KeyPair) Seed() string {
	return util.ToBase58(kp.seed)
}

// SeedBytes returns bytes of a seed of a keypair
func (kp KeyPair) SeedBytes() []byte {
	return kp.seed
}

// String returns the base58 string of the private key in a keypair
func (kp KeyPair) String() string {
	return util.ToBase58(kp.PrivateKey.PrivateKeyBytes())
}

// KeyType returns the algorithm type of a keypair
func (kp KeyPair) KeyType() string {
	// HARDCODE: only one algorithm type is in the system now.
	return "ed25519"
}

// Return the network of a keypair
func (kp KeyPair) Network() string {
	// FIXME: it is better to use variables in bitmarkd for determine header size.
	if len(kp.seed) < 4 {
		return "unknown"
	}

	networkByte := kp.seed[3]
	switch networkByte {
	case variantLivenet:
		return "livenet"
	case variantTestnet:
		return "testnet"
	default:
		return "unknown"
	}
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
		seed:       util.FromBase58(seed),
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

	p, err := account.PrivateKeyFromBase58Seed(util.ToBase58(seedBytes))
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: p,
		seed:       seedBytes,
	}, nil
}
