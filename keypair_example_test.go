package bitmarklib_test

import (
	"fmt"
	"github.com/bitmark-inc/go-bitmarklib"
	"log"
)

func ExampleNewKeyPairFromBase58Seed() {
	seed := "5XEECseCzmTE1SeJb5tQCpDK6cyDx2qKinCg5BNFgWnn3d9FjsEVDHZ"
	kp, err := bitmarklib.NewKeyPairFromBase58Seed(seed)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(kp)
	// Output: 3x5n7S3MBG2jFWvuxxXMNAVavxKipXrH6vBtnoCDqPAMtZwzYCLPKq4NY7zoZ6HQ5CRQMNV2i3srL81XuskLy3xt
}

func ExampleNewKeyPairFromKIF() {
	kif := "TLpSduNW7r3zrkc9foneYs2zTkikVPnY1SNZaYbispusdFmittczPGKDLKtzH"
	kp, err := bitmarklib.NewKeyPairFromKIF(kif)
	if err != nil {
		log.Fatal(err)
	}
	if !kp.PrivateKey.IsTesting() {
		log.Fatal(err)
	}
	fmt.Println(kp)
	// Output: 5xJrqMvvHixJ8SVJyXgQDPiW46Ghbxkk6EkqGRqRnj7FUh5bsKPi2vejjGkTaM5ed24Q14bW4sx2ce38HVD16Jx8
}
