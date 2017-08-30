package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	bitmarklib "github.com/bitmark-inc/go-bitmarklib"
)

var (
	seed string

	msg  string
	skey string

	dsrc string
	ddst string

	sseed string
	rseed string

	enckey    string
	enckeysig string
	keysig    string
)

func mustDecodeHexString(src string) []byte {
	dst, err := hex.DecodeString(src)
	if err != nil {
		panic(err)
	}

	return dst
}

func main() {
	subcmd := flag.NewFlagSet("subcmd", flag.ExitOnError)

	subcmd.StringVar(&seed, "seed", "3e96d0993e1c4291899f2867c77eca73f2645d8488c2ce6012b4328cc00abf01", "the hex encoded seed to generate keypairs")

	subcmd.StringVar(&sseed, "sseed", "", "the hex encoded seed to generate keypairs for the sender")
	subcmd.StringVar(&rseed, "rseed", "", "the hex encoded seed to generate keypairs for the recipient")

	subcmd.StringVar(&msg, "msg", "", "the hex encoded message to be encrypted")
	subcmd.StringVar(&skey, "skey", "", "the hex encoded session key")

	subcmd.StringVar(&dsrc, "dsrc", "", "the path to read the encrypted file")
	subcmd.StringVar(&ddst, "ddst", "", "the path to write the decrypted file")

	subcmd.StringVar(&enckey, "enckey", "", "the encrypted session key to decrypt the file")
	subcmd.StringVar(&enckeysig, "enckeysig", "", "the signature of the encrypted session key")
	subcmd.StringVar(&keysig, "keysig", "", "the signature of the session key")

	subcmd.Parse(os.Args[2:])

	senderSeed := mustDecodeHexString(sseed)
	sAuthKeypair, _ := bitmarklib.NewKeyPairFromCoreSeed(senderSeed, true, bitmarklib.ED25519)
	sEncrKeypair, _ := bitmarklib.NewEncrKeyPairFromSeed(senderSeed)

	recipientSeed := mustDecodeHexString(rseed)
	rEncrKeypair, _ := bitmarklib.NewEncrKeyPairFromSeed(recipientSeed)

	switch os.Args[1] {
	case "genkeypair":
		s := mustDecodeHexString(seed)
		actKeyPair, _ := bitmarklib.NewKeyPairFromCoreSeed(s, true, bitmarklib.ED25519)
		acsKeyPair, _ := bitmarklib.NewEncrKeyPairFromSeed(s)

		fmt.Println("\n→ auth keypair")
		fmt.Printf("\tprivate key: %s\n", hex.EncodeToString(actKeyPair.PrivateKeyBytes()))
		fmt.Printf("\tpublic key:  %s\n", hex.EncodeToString(actKeyPair.Account().PublicKeyBytes()))

		fmt.Println("\n→ encr keypair")
		fmt.Printf("\tprivate key: %s\n", hex.EncodeToString(acsKeyPair.PrivateKey[:]))
		fmt.Printf("\tpublic key:  %s\n", hex.EncodeToString(acsKeyPair.PublicKey[:]))
		fmt.Println("")
	case "encrypt":
		sessKey, _ := bitmarklib.SessionKeyFromHex(bitmarklib.Chacha20poly1305, skey)
		content, _ := bitmarklib.EncryptAssetFile(mustDecodeHexString(msg), sessKey, sAuthKeypair.PrivateKeyBytes())
		data, _ := bitmarklib.CreateSessionData(sessKey, rEncrKeypair.PublicKey, sEncrKeypair.PrivateKey, sAuthKeypair.PrivateKeyBytes())

		fmt.Println("\n→ session data")
		fmt.Printf("\tenckey:    %s\n", hex.EncodeToString(data.EncryptedSessionKey))
		fmt.Printf("\tenckeysig: %s\n", hex.EncodeToString(data.EncryptedSessionKeySignature))
		fmt.Printf("\tkeysig:    %s\n", hex.EncodeToString(data.SessionKeySignature))
		fmt.Println("→ encrypted file content")
		fmt.Printf("%s\n\n", hex.EncodeToString(content))
	case "decrypt":
		data := &bitmarklib.SessionData{
			EncryptedSessionKey:          mustDecodeHexString(enckey),
			EncryptedSessionKeySignature: mustDecodeHexString(enckeysig),
			SessionKeySignature:          mustDecodeHexString(keysig),
		}
		sessKey, err := bitmarklib.SessionKeyFromSessionData(data, sEncrKeypair.PublicKey, rEncrKeypair.PrivateKey, sAuthKeypair.Account().PublicKeyBytes())
		if err != nil {
			fmt.Printf("invalid session data: %v\n", err)
		}

		content, err := ioutil.ReadFile(dsrc)
		if err != nil {
			fmt.Printf("unable to read the file: %v\n", err)
		}

		plaintext, err := bitmarklib.DecryptAssetFile(content, sessKey, sAuthKeypair.Account().PublicKeyBytes())
		if err != nil {
			fmt.Printf("unable to decrypt the file: %v\n", err)
		}

		f, err := os.Create(ddst)
		defer f.Close()
		if err != nil {
			fmt.Printf("unable to write the decrypted file: %v\n", err)
			fmt.Printf("%v\n", err)
		}
		f.Write(plaintext)
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}
}
