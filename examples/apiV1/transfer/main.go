package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/bitmark-inc/go-bitmarklib"
)

const (
	BDGW_HOST = "api.test.bitmark.com"
)

func requestTransfer(client *http.Client, transferBody interface{}) error {
	actionUrl := url.URL{
		Scheme: "https",
		Host:   BDGW_HOST,
		Path:   "/v1/transfer",
	}

	buf := bytes.Buffer{}
	e := json.NewEncoder(&buf)
	err := e.Encode(transferBody)
	if err != nil {
		return err
	}

	r, err := client.Post(actionUrl.String(), "application/json", &buf)
	if err != nil {
		log.Fatalf("request action error: %s", err)
	}
	defer r.Body.Close()

	resultBuf := &bytes.Buffer{}
	_, err = io.Copy(resultBuf, r.Body)
	if err != nil {
		return err
	}

	fmt.Println(resultBuf.String())
	if r.StatusCode != http.StatusOK {
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

	// publicKey := "fa447039da1cb03c0e48ab48dec69769d3affce01a5565a4b64a5d920f3c21a9"
	address := "fqN6WnjUaekfrqBvvmsjVskoqXnhJ632xJPHzdSgReC6bhZGuP"

	transfer, err := bitmarklib.NewTransfer(*txId, address, true)
	if err != nil {
		log.Fatal(err)
	}
	err = transfer.Sign(keypair)
	if err != nil {
		log.Fatal(err)
	}

	v := map[string]interface{}{
		"transfer": transfer,
	}

	err = requestTransfer(client, v)
	if err != nil {
		log.Fatal(err)
	}
}
