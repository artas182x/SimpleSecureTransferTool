package main

import (
	"fmt"
	"time"
)

func main() {

	/*teststr := "Example text"

	privKey, pubkey, _ := GenerateKeyPair(4096)

	testbyte := []byte(teststr)

	result, err := EncryptRSA(testbyte, pubkey)

	if err != nil {
		log.Fatal(err)
	}

	println(string(result))
	println(string(privKey))
	println(string(pubkey))

	for i := 0; i < len(privKey); i++ {
		privKey[i] = byte(i)
	}

	decrypted, err := DecryptRSA(result, privKey)

	if err != nil {
		log.Fatal(err)
	}

	println(string(decrypted))*/

	/*key, _ := hex.DecodeString("7368616e676520746869732070617373")
	msg := "Test string - testing encryption and decryption"
	var encrypted []byte
	var decrypted2 string
	var err error

	if encrypted, err = EncryptTextMessage(key, msg, CBC); err != nil {
		log.Fatal(err)
	}

	if decrypted2, err = DecryptTextMessage(key, encrypted, CBC); err != nil {
		log.Fatal(err)
	}

	println(decrypted2)*/

	encMess := EncryptedMessageHandler(32, CBC)
	encMess.LoadKeys()

	netClient := NetClientInit(27001, encMess)

	encMess2 := EncryptedMessageHandler(32, CBC)
	encMess2.LoadKeys()

	netClient2 := NetClientInit(27002, encMess2)

	go netClient.NetclientListen()
	go netClient2.NetclientListen()

	for i := 0; i < 10; i++ {
		time.Sleep(1000)
	}

	err := netClient.SendHello("127.0.0.1:27002")
	if err != nil {
		fmt.Println(err.Error())
	}

	netClient.SendTextMessage("TEST")

}
