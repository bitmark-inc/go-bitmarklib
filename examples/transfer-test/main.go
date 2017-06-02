package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/bitmark-inc/go-bitmarklib"
	"github.com/bitmark-inc/go-programs/bitmarkd-gateway/action"
)

const (
	BDGW_HOST = "localhost:8087"
)

func requestToken(client *http.Client) (string, error) {
	actionUrl := url.URL{
		Scheme: "https",
		Host:   BDGW_HOST,
		Path:   "/token",
	}
	r, err := client.Get(actionUrl.String())
	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return "", fmt.Errorf(r.Status)
	}

	var v map[string]string
	d := json.NewDecoder(r.Body)
	err = d.Decode(&v)
	if err != nil {
		return "", err
	}
	if token, ok := v["t"]; ok {
		return token, nil
	} else {
		return "", fmt.Errorf("token is not available")
	}
}

func requestTransfer(client *http.Client, a action.Action) error {
	actionUrl := url.URL{
		Scheme: "https",
		Host:   BDGW_HOST,
		Path:   "/action",
	}

	buf := bytes.Buffer{}
	e := json.NewEncoder(&buf)
	err := e.Encode(&a)
	if err != nil {
		return err
	}

	r, err := client.Post(actionUrl.String(), "application/json", &buf)
	if err != nil {
		log.Fatalf("request action error: %s", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		return fmt.Errorf(r.Status)
	}
	return nil
}

func main() {
	seed := "GUgLnRy3Fns6Twns2THBsZjdRWGsaDXENq18mZzHuTPy"
	keypair, err := bitmarklib.NewKeyPairFromBase58Seed(seed, true, bitmarklib.ED25519)
	if err != nil {
		log.Fatal(err)
	}

	txId := flag.String("txId", "", "transaction id")
	flag.Parse()

	if *txId == "" {
		log.Fatal("empty transaction id")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	token, err := requestToken(client)
	if err != nil {
		log.Fatal(err)
	}

	newOwnerKey := "fa447039da1cb03c0e48ab48dec69769d3affce01a5565a4b64a5d920f3c21a9"
	transfer, err := bitmarklib.NewTransfer(*txId, newOwnerKey)
	if err != nil {
		log.Fatal(err)
	}
	err = transfer.Sign(keypair)
	if err != nil {
		log.Fatal(err)
	}

	a := action.Action{
		Type:    "transfer",
		Token:   token,
		Owner:   keypair.Account().String(),
		Payload: transfer.String(),
	}

	a.Sign(keypair.PrivateKeyBytes())

	err = requestTransfer(client, a)
	if err != nil {
		log.Fatal(err)
	}
}
