package bitmarklib

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestAuthKeyCreation(t *testing.T) {
	seed, _ := SeedFromBase58("5XEECsYGDXGWmBnSrExALVTWhzj9mNXxs3y98TgrtkLi6GE4qfoammV")
	authKey, err := NewAuthKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	if hex.EncodeToString(authKey.PrivateKeyBytes()[:32]) != "ae13ec8df21e96f158021e416c1051593b26872f8c485c5711295601f56eaeff" {
		t.Error("wrong auth seed")
	}

	if hex.EncodeToString(authKey.PublicKeyBytes()) != "b562add440ba24611b2c39ec442b4bab77776102191941278e56abca08254049" {
		t.Error("wrong auth public key")
	}

	if authKey.AccountNumber() != "fK2bofQaQdj2KZmRVwh3Gv7KrDuckcbet9deCPZQs6CEdYTF11" {
		t.Error("wrong account number")
	}

	// livenet
	seed, _ = SeedFromBase58("5XEECqbX3HpUum7DiRNTRuqWkg8NrFvFDM8GLpckebep6cDgM5eHqzd")
	authKey, err = NewAuthKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	if hex.EncodeToString(authKey.PrivateKeyBytes()[:32]) != "ae13ec8df21e96f158021e416c1051593b26872f8c485c5711295601f56eaeff" {
		t.Error("wrong auth seed")
	}

	if hex.EncodeToString(authKey.PublicKeyBytes()) != "b562add440ba24611b2c39ec442b4bab77776102191941278e56abca08254049" {
		t.Error("wrong public key")
	}

	if authKey.AccountNumber() != "bRYFLmLsZHGkgQMcLhh8diZVczUKLvr5c1R9u1mRZ5RFTn78ko" {
		t.Error("wrong account number")
	}
}

func TestEncrKeyCreation(t *testing.T) {
	seed, _ := SeedFromBase58("5XEECsYGDXGWmBnSrExALVTWhzj9mNXxs3y98TgrtkLi6GE4qfoammV")
	encrKey, err := NewEncrKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	if hex.EncodeToString(encrKey.PrivateKeyBytes()) != "b8342b840717a241366ea2f9ba838bae3b26872f8c485c5711295601f56eaef0" {
		t.Error("wrong encr seed")
	}

	if hex.EncodeToString(encrKey.PublicKeyBytes()) != "54b992f187e3687c1bda1fd30783b6de2163688e8a9042124fe9aad565ded406" {
		t.Error("wrong encr public key")
	}
}

func TestEncrKeyFunction(t *testing.T) {
	seed, _ := SeedFromBase58("5XEECsYGDXGWmBnSrExALVTWhzj9mNXxs3y98TgrtkLi6GE4qfoammV")
	encrKey, _ := NewEncrKey(seed)

	message := "Hello, world!"
	ciphertext, _ := encrKey.Encrypt([]byte(message), encrKey.PublicKeyBytes())
	plaintext, _ := encrKey.Decrypt(ciphertext, encrKey.PublicKeyBytes())

	if string(plaintext) != message {
		t.Error("encryption/decryption failed")
	}
}

func mustDecodeHex(str string) []byte {
	b, err := hex.DecodeString("3e96d0993e1c4291899f2867c77eca73f2645d8488c2ce6012b4328cc00abf01")
	if err != nil {
		panic(err)
	}
	return b
}
