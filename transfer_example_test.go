package bitmarklib_test

import (
	"fmt"
	"github.com/bitmark-inc/go-bitmarklib"
	"log"
)

func Example_createTransfer() {
	seed := "5XEECseCzmTE1SeJb5tQCpDK6cyDx2qKinCg5BNFgWnn3d9FjsEVDHZ"
	kp, err := bitmarklib.NewKeyPairFromBase58Seed(seed)
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
	// Output: eyJsaW5rIjoiNjc3NjU5OWE1ZmQ0ZjJhZGUxY2E4N2VlNWZmZmQwMjk1YmI2OWIxOTY5ZmZhYjFlYzA0MmE1ZjcxZWY3NDIwOSIsInBheW1lbnQiOm51bGwsIm93bmVyIjoiZnFONldualVhZWtmcnFCdnZtc2pWc2tvcVhuaEo2MzJ4SlBIemRTZ1JlQzZiaFpHdVAiLCJzaWduYXR1cmUiOiJkNjQxMzlhOTcxMjE3ZDJkNjE3ZDdmYmUwMDYwZWYwNDk4ZjA2OGY3N2IyYzIxNzNmYjhmYzEwN2NlYzRiNWQ4ZjNkNzM0OTJjZmZlNzY4MDM1M2YyMTljN2ZjYmY1ZTJjYzllNDc3NWNiMWJkODg5NGE4ODFjOTlmNGVjMzUwMiJ9
}
