package bitmarklib

import (
	"encoding/hex"
	"fmt"
	"github.com/bitmark-inc/bitmarkd/account"
	"github.com/bitmark-inc/bitmarkd/merkle"
	"github.com/bitmark-inc/bitmarkd/transactionrecord"
	"golang.org/x/crypto/ed25519"
)

type Transfer struct {
	*transactionrecord.BitmarkTransfer
}

func NewTransfer(txId, newOwner string) (*Transfer, error) {
	link := merkle.Digest{}
	link.UnmarshalText([]byte(txId))

	newOwnerBytes, err := hex.DecodeString(newOwner)
	if err != nil {
		return nil, err
	}
	newOwnerAccount := &account.Account{
		AccountInterface: &account.ED25519Account{
			Test:      true,
			PublicKey: newOwnerBytes,
		},
	}

	t := &Transfer{
		&transactionrecord.BitmarkTransfer{
			Link:      link,
			Owner:     newOwnerAccount,
			Signature: []byte{},
		},
	}

	return t, nil
}

func (t *Transfer) Sign(privateKey *account.PrivateKey) error {
	packed, _ := t.Pack(t.Owner)
	if nil == packed {
		return fmt.Errorf("fail to pack transfer")
	}

	ownerAccount := &account.Account{
		AccountInterface: &account.ED25519Account{
			Test:      true,
			PublicKey: privateKey.Account().PublicKeyBytes(),
		},
	}

	t.Signature = ed25519.Sign(privateKey.PrivateKeyBytes(), packed)
	_, err := t.Pack(ownerAccount)
	return err
}
