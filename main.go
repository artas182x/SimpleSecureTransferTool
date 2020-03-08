package main

import (
	"fmt"
	"log"
	"os"
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

	exampleNetclient()

}

func exampleNetclient() {
	encMess := EncryptedMessageHandler(32, ECB)
	encMess.LoadKeys()

	netClient := NetClientInit(27001, encMess)

	encMess2 := EncryptedMessageHandler(32, ECB)
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
		netClient.connected = false
		//TODO IN GUI: Handle error, mark connection as disconnected
	}

	//	netClient.SendTextMessage("TEST")

	netClient2.receiveDir = "test"
	file, _ := os.Open("/home/artas182x/Downloads/Lab4.zip")
	netClient.SendFile(file)
}

func exampleFileEncryptionAndDecryption() {
	encMess := EncryptedMessageHandler(32, CBC)
	file, err := os.Open("main.go")
	if err != nil {
		log.Fatal(err)
	}

	fileEncrypted, err := os.Create("main.go.encrypted")
	if err != nil {
		log.Fatal(err)
	}

	fileDecrypted, err := os.Create("main.go.decrypted")
	if err != nil {
		log.Fatal(err)
	}

	EncryptFile(encMess.aesKey, encMess.iv, file, fileEncrypted, encMess.cipherMode)
	fileEncrypted.Close()
	fileEncrypted, err = os.Open("main.go.encrypted")
	if err != nil {
		log.Fatal(err)
	}
	DecryptFile(encMess.aesKey, encMess.iv, fileEncrypted, fileDecrypted, encMess.cipherMode)
}
