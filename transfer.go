package bitmarklib

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bitmark-inc/bitmarkd/account"
	"github.com/bitmark-inc/bitmarkd/merkle"
	"github.com/bitmark-inc/bitmarkd/transactionrecord"
	"golang.org/x/crypto/ed25519"
)

// Transfer is made for issue transfering
type Transfer struct {
	*transactionrecord.BitmarkTransfer
}

// NewTransfer will return a Transfer struct
func NewTransfer(txId, newOwner string, test bool) (*Transfer, error) {
	link := merkle.Digest{}
	link.UnmarshalText([]byte(txId))

	newOwnerBytes, err := hex.DecodeString(newOwner)
	if err != nil {
		return nil, err
	}
	newOwnerAccount := &account.Account{
		AccountInterface: &account.ED25519Account{
			Test:      test,
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

// Sign will sign a transfer with an owner private key. This action
// won't check whether a transfer belongs to an owner.
func (t *Transfer) Sign(kp *KeyPair) error {
	packed, _ := t.Pack(t.Owner)
	if nil == packed {
		return fmt.Errorf("fail to pack transfer")
	}

	ownerAccount := kp.Account()
	t.Signature = ed25519.Sign(kp.PrivateKeyBytes(), packed)
	_, err := t.Pack(ownerAccount)
	return err
}

// Return the base64 string of the JSON object. Return empty if there is
// something wrong.
func (t Transfer) String() string {
	b, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	payload := base64.StdEncoding.EncodeToString(b)
	return payload
}
