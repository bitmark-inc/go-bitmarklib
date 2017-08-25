package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	bitmarklib "github.com/bitmark-inc/go-bitmarklib"
)

var (
	seed      string
	msg       string
	encmsg    string
	sseed     string
	rseed     string
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

	subcmd.StringVar(&seed, "seed", "3e96d0993e1c4291899f2867c77eca73f2645d8488c2ce6012b4328cc00abf01", "the hex encoded to generate keypairs")

	subcmd.StringVar(&msg, "msg", "hellow world", "the message to be encrypted")
	subcmd.StringVar(&encmsg, "encmsg", "", "the message to be decrypted")

	subcmd.StringVar(&sseed, "sseed", "5e1913a6fc45769bb18a5b85d81d26b7040e94754c2493f0194d62da324303f3", "the hex encoded to generate keypairs for the sender")
	subcmd.StringVar(&rseed, "rseed", "e31100fe479949ddfe292f9755aeea78037e5beb1c423311cb9ffdc74625050b", "the hex encoded seed to generate keypairs for the recipient")

	subcmd.StringVar(&enckey, "enckey", "", "the encrypted session key to decrypt the file")
	subcmd.StringVar(&enckeysig, "enckeysig", "", "the signature of the encrypted session key")
	subcmd.StringVar(&keysig, "keysig", "", "the signature of the session key")

	subcmd.Parse(os.Args[2:])

	senderSeed := mustDecodeHexString(sseed)
	senderAccountKeypair, _ := bitmarklib.NewKeyPairFromCoreSeed(senderSeed, true, bitmarklib.ED25519)
	senderAccessKeypair, _ := bitmarklib.NewAccessKeyPairFromSeed(senderSeed)

	recipientSeed := mustDecodeHexString(rseed)
	recipientAcsKeypair, _ := bitmarklib.NewAccessKeyPairFromSeed(recipientSeed)

	switch os.Args[1] {
	case "genkeypair":
		s := mustDecodeHexString(seed)
		actKeyPair, _ := bitmarklib.NewKeyPairFromCoreSeed(s, true, bitmarklib.ED25519)
		acsKeyPair, _ := bitmarklib.NewAccessKeyPairFromSeed(s)

		fmt.Println("\n→ bitmark account keypair")
		fmt.Printf("\tprivate key: %s\n", hex.EncodeToString(actKeyPair.PrivateKeyBytes()))
		fmt.Printf("\tpublic key:  %s\n", hex.EncodeToString(actKeyPair.Account().PublicKeyBytes()))
		fmt.Println("")
		fmt.Println("→ asset access keypair")
		fmt.Printf("\tprivate key: %s\n", hex.EncodeToString(acsKeyPair.PrivateKey[:]))
		fmt.Printf("\tpublic key:  %s\n", hex.EncodeToString(acsKeyPair.PublicKey[:]))
		fmt.Println("")
	case "encrypt":
		skey, _ := bitmarklib.NewChaCha20SessionKey()
		encryptedMsg, _ := bitmarklib.CreateEncryptedMessage([]byte(msg), skey, senderAccountKeypair.PrivateKeyBytes())
		sessionData, _ := bitmarklib.CreateSessionData(skey, recipientAcsKeypair.PublicKey, senderAccessKeypair.PrivateKey, senderAccountKeypair.PrivateKeyBytes())

		fmt.Println("\n→ session data")
		fmt.Printf("\tenckey:    %s\n", hex.EncodeToString(sessionData.EncryptedSessionKey))
		fmt.Printf("\tenckeysig: %s\n", hex.EncodeToString(sessionData.EncryptedSessionKeySignature))
		fmt.Printf("\tkeysig:    %s\n", hex.EncodeToString(sessionData.SessionKeySignature))
		fmt.Println("→ encrypted message")
		fmt.Printf("%s\n\n", hex.EncodeToString(encryptedMsg))
	case "decrypt":
		data := &bitmarklib.SessionData{
			EncryptedSessionKey:          mustDecodeHexString(enckey),
			EncryptedSessionKeySignature: mustDecodeHexString(enckeysig),
			SessionKeySignature:          mustDecodeHexString(keysig),
		}
		sessionKey, _ := bitmarklib.ParseSessionData(data, senderAccessKeypair.PublicKey, recipientAcsKeypair.PrivateKey, senderAccountKeypair.Account().PublicKeyBytes())

		r, err := bitmarklib.DecryptEncryptedFile(mustDecodeHexString(encmsg), sessionKey, senderAccountKeypair.Account().PublicKeyBytes())
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println("\n→ decrypted message")
		fmt.Printf("%s\n\n", string(r))
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}
}
