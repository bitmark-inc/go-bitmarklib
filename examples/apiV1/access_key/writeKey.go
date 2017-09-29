package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/bitmark-inc/go-bitmarklib"
)

const (
	API_URL = "https://api.devel.bitmark.com"
)

func NewSeedFromHexString(seed string) ([32]byte, error) {
	rootSeed := [32]byte{}
	b, err := hex.DecodeString(seed)
	if err != nil {
		return rootSeed, err
	}

	if len(b) != 32 {
		return rootSeed, fmt.Errorf("invalid length of bitmark account")
	}
	copy(rootSeed[:], b[:32])
	return rootSeed, nil
}

func main() {

	now := time.Now().Unix()
	accessKey := fmt.Sprintf("%064x", now)
	seed, err := NewSeedFromHexString(accessKey)

	inTest := true
	keypair, err := bitmarklib.NewKeyPairFromSeed(seed[:], inTest, bitmarklib.ED25519)
	if err != nil {
		log.Fatalf("Fail to generate account key: %s", err.Error())
	}
	log.Printf("Auth Account: %s", keypair.Account().String())

	account := keypair.Account().String()
	accessKeyByte, _ := hex.DecodeString(accessKey)

	signature := ed25519.Sign(keypair.PrivateKeyBytes(), accessKeyByte)
	signatureString := hex.EncodeToString(signature)

	u, err := url.Parse(API_URL)
	if err != nil {
		log.Fatal(err)
	}
	u.Path = fmt.Sprintf("/v1/encryption_keys/%s", account)

	req := map[string]string{
		"encryption_pubkey": accessKey,
		"signature":         signatureString,
	}

	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	err = e.Encode(req)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Request Body: %s", buf.String())
	resp, err := http.Post(u.String(), "application/json", &buf)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Start request from:", u.String())
	if resp.StatusCode != 200 {
		log.Printf("Fail to store api: %d", resp.StatusCode)
	}

	var ret map[string]interface{}
	d := json.NewDecoder(resp.Body)
	d.Decode(&ret)
	log.Printf("Result: %+v\n", ret)
}
