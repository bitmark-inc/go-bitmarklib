package main

import (
	"flag"
	"fmt"
	"os"

	bitmarklib "github.com/bitmark-inc/go-bitmarklib"
)

var (
	src  string
	dst  string
	seed string
	skey string
)

func main() {
	subcmd := flag.NewFlagSet("subcmd", flag.ExitOnError)
	subcmd.StringVar(&src, "src", "", "the path to the en/decryption file")
	subcmd.StringVar(&dst, "dst", "", "the path to the en/decryption file")
	subcmd.StringVar(&seed, "seed", "GUgLnRy3Fns6Twns2THBsZjdRWGsaDXENq18mZzHuTPy", "the seed to generate the bitmark keypair")
	subcmd.StringVar(&skey, "skey", "", "the session key to decrypt the file")
	subcmd.Parse(os.Args[2:])

	switch os.Args[1] {
	case "encrypt":
		sessionKey, _ := bitmarklib.NewChaCha20SessionKey()
		accountKeypair, _ := bitmarklib.NewKeyPairFromBase58Seed(seed, true, bitmarklib.ED25519)

		err := bitmarklib.CreateEncryptedFile(src, dst, sessionKey, accountKeypair.PrivateKeyBytes())
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		fmt.Println(sessionKey.String())
	case "decrypt":
		sessionKey, _ := bitmarklib.SessionKeyFromHex(bitmarklib.Chacha20poly1305, skey)
		accountKeypair, _ := bitmarklib.NewKeyPairFromBase58Seed(seed, true, bitmarklib.ED25519)

		err := bitmarklib.CreateDecryptedFile(src, dst, sessionKey, accountKeypair.Account().PublicKeyBytes())
		if err != nil {
			fmt.Println(err.Error())
		}
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}
}
