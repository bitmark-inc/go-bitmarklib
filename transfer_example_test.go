package bitmarklib_test

import (
	"fmt"
	"github.com/bitmark-inc/go-bitmarklib"
	"log"
)

func Example_createTransfer() {
	seed := "8VNLU6LSMjnCfMNHG9YftLV1TVWzAphfCSwJsf351974"
	kp, err := bitmarklib.NewKeyPairFromBase58Seed(seed, true, bitmarklib.ED25519)
	if err != nil {
		log.Fatal(err)
	}

	transfer, err := bitmarklib.NewTransfer("6776599a5fd4f2ade1ca87ee5fffd0295bb69b1969ffab1ec042a5f71ef74209", "fa447039da1cb03c0e48ab48dec69769d3affce01a5565a4b64a5d920f3c21a9")
	if err != nil {
		log.Fatal(err)
	}
	err = transfer.Sign(kp.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(transfer)
	// Output: eyJsaW5rIjoiNjc3NjU5OWE1ZmQ0ZjJhZGUxY2E4N2VlNWZmZmQwMjk1YmI2OWIxOTY5ZmZhYjFlYzA0MmE1ZjcxZWY3NDIwOSIsInBheW1lbnQiOm51bGwsIm93bmVyIjoiZnFONldualVhZWtmcnFCdnZtc2pWc2tvcVhuaEo2MzJ4SlBIemRTZ1JlQzZiaFpHdVAiLCJzaWduYXR1cmUiOiJlMTQ2NDJjOWI5ZjBlMTQwOWFkMmEwYjlhMjQ4YmYzNTZlZTlhOTg1NGE0YzRmNjAyZDNkZThkYWNjZjVjZDExZWUyNzBjOTQ1YzdkM2JiNThhM2ZjMjg1OGMxMDliZGI5YWQzMTkxNGQyZTFhMTg2NzM4M2ZkY2QxZjMwMGYwZSJ9
}
