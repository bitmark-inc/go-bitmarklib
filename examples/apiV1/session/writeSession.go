package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"log"
	"net/http"
	"net/url"

	"github.com/bitmark-inc/go-bitmarklib"
)

const (
	API_URL = "https://api.devel.bitmark.com"
)

func main() {
	bitmarkId := flag.String("bitmarkId", "", "bitmark id")
	account := flag.String("account", "", "to account")
	flag.Parse()

	seed := "GUgLnRy3Fns6Twns2THBsZjdRWGsaDXENq18mZzHuTPy"
	keypair, err := bitmarklib.NewKeyPairFromBase58Seed(seed, true, bitmarklib.ED25519)
	if err != nil {
		log.Fatal(err)
	}

	data := `{"enc_skey": "key1", "enc_skey_sig": "sig1", "skey_sig": "sig2"}`
	if *account == "" {
		*account = keypair.Account().String()
	}
	signatureOrigin := ed25519.Sign(keypair.PrivateKeyBytes(), []byte(data))
	signature := hex.EncodeToString(signatureOrigin)

	u, err := url.Parse(API_URL)
	if err != nil {
		log.Fatal(err)
	}
	u.Path = fmt.Sprintf("/v1/session/%s", *bitmarkId)
	q := url.Values{
		"account_no": []string{*account},
	}
	u.RawQuery = q.Encode()

	reqBody := map[string]string{
		"data":      data,
		"signature": signature,
	}

	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	err = e.Encode(reqBody)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Request body: %+v", buf.String())
	req, _ := http.NewRequest("PUT", u.String(), &buf)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(u.String())
	if resp.StatusCode != 200 {
		log.Printf("Fail to store api: %d", resp.StatusCode)
	}

	var ret map[string]interface{}
	d := json.NewDecoder(resp.Body)
	d.Decode(&ret)
	log.Printf("Result: %+v\n", ret)
}
