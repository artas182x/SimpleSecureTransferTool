package main

import (
	"encoding/hex"
	"log"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	teststr := "Example text"

	privKey, pubkey, _ := GenerateKeyPair(4096)

	testbyte := []byte(teststr)

	result, err := EncryptData(testbyte, pubkey)

	if err != nil {
		log.Fatal(err)
	}

	println(string(result))
	println(string(privKey))
	println(string(pubkey))

	for i := 0; i < len(privKey); i++ {
		privKey[0] = byte(i)
	}

	decrypted, err := DecryptData(result, privKey)

	if err != nil {
		log.Fatal(err)
	}

	println(string(decrypted))

	key, _ := hex.DecodeString("7368616e676520746869732070617373")
	msg := "Test string - testing encryption and decryption"
	var encrypted []byte
	var decrypted2 string

	if encrypted, err = EncryptTextMessage(key, msg, ECB); err != nil {
		log.Fatal(err)
	}

	if decrypted2, err = DecryptTextMessage(key, encrypted, ECB); err != nil {
		log.Fatal(err)
	}

	println(decrypted2)

}
