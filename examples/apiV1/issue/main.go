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

	"github.com/bitmark-inc/go-bitmarklib"
)

var (
	dummySignature = []byte{}
)

const (
	BDGW_HOST = "api.test.bitmark.com"
)

func requestAction(client *http.Client, issueBody interface{}) error {
	issueUrl := url.URL{
		Scheme: "https",
		Host:   BDGW_HOST,
		Path:   "/v1/issue",
	}

	buf := bytes.Buffer{}
	e := json.NewEncoder(&buf)
	err := e.Encode(issueBody)
	if err != nil {
		return err
	}

	r, err := client.Post(issueUrl.String(), "application/json", &buf)
	if err != nil {
		log.Fatalf("request action error: %s", err)
	}
	defer r.Body.Close()

	resultBuf := &bytes.Buffer{}
	_, err = io.Copy(resultBuf, r.Body)
	if err != nil {
		fmt.Println("err:", err.Error())
	}
	fmt.Println("result:", resultBuf.String())

	if r.StatusCode >= 300 {
		return fmt.Errorf(r.Status)
	}
	return nil
}

type IssueCreateArgument struct {
	Assets []bitmarklib.Asset
	Issues []bitmarklib.Issue
}

func main() {
	seed := "GUgLnRy3Fns6Twns2THBsZjdRWGsaDXENq18mZzHuTPy"
	keypair, err := bitmarklib.NewKeyPairFromBase58Seed(seed, true, bitmarklib.ED25519)
	if err != nil {
		log.Fatal(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	asset := bitmarklib.NewAsset("test", fmt.Sprint(time.Now().Unix()))

	if err != nil {
		log.Fatal(err)
	}

	err = asset.Sign(keypair)
	if err != nil {
		log.Fatal(err)
	}

	quantity := 1
	issues := make([]bitmarklib.Issue, quantity)

	for i := 0; i < quantity; i++ {
		issue := bitmarklib.NewIssue(asset.AssetIndex())
		err := issue.Sign(keypair)
		if err != nil {
			continue
		}
		issues[i] = issue
	}

	r := IssueCreateArgument{
		Assets: []bitmarklib.Asset{asset},
		Issues: issues,
	}

	err = requestAction(client, r)
	if err != nil {
		log.Fatal(err)
	}
}
