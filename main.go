package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
)

func main() {
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
