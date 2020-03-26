package main

import (
	"bufio"
	"flag"
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

	// exampleNetclient()
	consoleModeFlag := flag.Bool("console", false, "Should app run in console mode")
	portFlag := flag.Int("port", 27002, "Port on which app should listen")
	connectAddr := flag.String("connect", "", "Address to which app should connect on start")
	flag.Parse()
	var nullGuiApp GUIApp
	reader := bufio.NewReader(os.Stdin)
	if *consoleModeFlag {
		fmt.Print("Password: ")
		os.MkdirAll("client", os.ModePerm)
		password, _ := reader.ReadString('\n')
		encryptor := EncryptedMessageHandler(32, ECB)
		err := encryptor.LoadKeys("client", password, &nullGuiApp)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No keypair available. Creating one")
				if err = encryptor.CreateKeys("client", password, &nullGuiApp); err != nil {
					fmt.Println(err.Error())
					return
				}
			}
		}
		netClient := NetClientInit(int32(*portFlag), encryptor)

		go netClient.NetClientListen(&nullGuiApp)
		if *connectAddr != "" {
			netClient.SendHello(*connectAddr)
		}
		for true {
			fmt.Print("Type message: ")
			message, _ := reader.ReadString('\n')
			netClient.SendTextMessage(message, &nullGuiApp)
		}
	} else {
		app := GUIAppNew(int32(*portFlag))
		app.RunGUI()
	}
}

//Example of started 2 clients on different ports. Normally one computer should have one client started. This is test case.
func exampleNetclient() {
	os.MkdirAll("test/client1", os.ModePerm)
	os.MkdirAll("test/client2", os.ModePerm)

	encMess := EncryptedMessageHandler(32, ECB)
	var nullGuiApp GUIApp
	//Example of handling keys in gui
	err := encMess.LoadKeys("test/client1", "123456", &nullGuiApp)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No keypair available. Creating one")
			if err = encMess.CreateKeys("test/client1", "123456", &nullGuiApp); err != nil {
				fmt.Println(err.Error())
				return
			}
		} else {
			//TODO GUI Bad keys - offer creating new
			fmt.Println(err.Error())
		}

	}

	netClient := NetClientInit(27001, encMess)

	encMess2 := EncryptedMessageHandler(32, ECB)

	err = encMess2.LoadKeys("test/client2", "1234567", &nullGuiApp)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No keypair available. Creating one")
			if err = encMess2.CreateKeys("test/client2", "1234567", &nullGuiApp); err != nil {
				fmt.Println(err.Error())
				return
			}
		} else {
			//TODO GUI Bad keys - offer creating new
			fmt.Println(err.Error())
		}

	}

	netClient2 := NetClientInit(27002, encMess2)

	go netClient.NetClientListen(&nullGuiApp)
	go netClient2.NetClientListen(&nullGuiApp)

	for i := 0; i < 10; i++ {
		time.Sleep(1000)
	}

	err = netClient.SendHello("127.0.0.1:27002")
	if err != nil {
		fmt.Println(err.Error())
		netClient.connected = false
		//TODO IN GUI: Handle error, mark connection as disconnected
	}

	netClient.SendTextMessage("TEST", &nullGuiApp)

	netClient2.receiveDir = "test"
	file, _ := os.Open("README.md")
	netClient.SendFile(file, &nullGuiApp)

	if netClient.Ping() {
		fmt.Println("Ping successful")
	}
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
	var nullGuiApp GUIApp
	err = EncryptFile(encMess.aesKey, encMess.iv, file, fileEncrypted, encMess.cipherMode, &nullGuiApp)
	if err != nil {
		log.Fatal(err)
	}

	fileEncrypted.Close()

	fileEncrypted, err = os.Open("main.go.encrypted")
	if err != nil {
		log.Fatal(err)
	}

	err = DecryptFile(encMess.aesKey, encMess.iv, fileEncrypted, fileDecrypted, encMess.cipherMode, &nullGuiApp)
	if err != nil {
		log.Fatal(err)
	}
}
