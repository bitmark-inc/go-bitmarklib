package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"encoding/base64"
	"github.com/bitmark-inc/bitmarkd/rpc"
	"github.com/bitmark-inc/bitmarkd/transactionrecord"
	"github.com/bitmark-inc/go-bitmarklib"
	"github.com/bitmark-inc/go-programs/bitmarkd-gateway/action"
)

var (
	dummySignature = []byte{}
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

func requestAction(client *http.Client, a action.Action) error {
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

	resultBuf := &bytes.Buffer{}
	_, err = io.Copy(resultBuf, r.Body)
	if err != nil {
		fmt.Println("err:", err.Error())
	}
	fmt.Println(resultBuf.String())

	if r.StatusCode >= 300 {
		return fmt.Errorf(r.Status)
	}
	return nil
}

func main() {
	seed := "5XEECtyEvdwvvgYo6TGkyQ59BG1zYZRkuLh6hhtebyaeKgMYxkn7DEt"
	keypair, err := bitmarklib.NewKeyPairFromBase58Seed(seed)
	if err != nil {
		log.Fatal(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	token, err := requestToken(client)
	if err != nil {
		log.Fatal(err)
	}

	asset := bitmarklib.NewAsset("test", fmt.Sprint(time.Now().Unix()))

	err = asset.SetMeta(map[string]string{
		"description": "test",
		"owner":       "jimjim",
	})
	if err != nil {
		log.Fatal(err)
	}

	err = asset.Sign(keypair)
	if err != nil {
		log.Fatal(err)
	}

	quantity := 1
	issues := make([]*transactionrecord.BitmarkIssue, quantity)
	for i := 0; i < quantity; i++ {
		issue := bitmarklib.NewIssue(asset.AssetIndex())
		issue.Sign(keypair)
		issues[i] = &issue.BitmarkIssue
	}

	r := rpc.CreateArguments{
		Assets: []*transactionrecord.AssetData{&asset.AssetData},
		Issues: issues,
	}

	b, err := json.Marshal(r)
	if err != nil {
		log.Fatal(err)
	}
	payload := base64.StdEncoding.EncodeToString(b)

	a := action.Action{
		Type:    "issue",
		Owner:   keypair.Account().String(),
		Token:   token,
		Payload: payload,
	}
	a.Sign(keypair.PrivateKeyBytes())

	err = requestAction(client, a)
	if err != nil {
		log.Fatal(err)
	}
}
