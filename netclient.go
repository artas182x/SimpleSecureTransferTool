package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
)

const listenport = 27001
const magicnumber uint32 = 0x1337ABCD

type packettype byte

var connected = false
var remoteIP net.Addr

// Structure representing packet types
const (
	//Client sends hello packet with public key
	HELLO = iota
	HELLORESPONSE
	CONNECTIONPROPERTIES
)

//NetclientlListener is main function for receiving connection. It's recommended to run it in separate thread
func NetclientlListener() {
	connection, err := net.Listen("tcp", fmt.Sprintf(":%d", listenport))
	if err != nil {
		panic(err)
	}
	defer connection.Close()
	for {
		c, err := connection.Accept()
		if err != nil {
			fmt.Println(err)
			c.Close()
			continue
		}

		var magicbuffer = make([]byte, 4)
		_, err = c.Read(magicbuffer)

		if err != nil {
			fmt.Println(err)
			c.Close()
			continue
		}

		if binary.LittleEndian.Uint32(magicbuffer) != magicnumber {
			c.Close()
			continue
		}
		if connected && c.RemoteAddr() != remoteIP {
			c.Close()
			continue
		}

		go handleIncomingConnection(c)

	}
}

func handleIncomingConnection(c net.Conn) {

	reader := bufio.NewReader(c)
	netData, err := reader.ReadByte()

	if err != nil {
		fmt.Println(err)
		return
	}

	buffer := make([]byte, 8096)

	switch netData {
	case HELLO:
		if !connected {
			_, err = reader.Read(buffer)

			if err != nil {
				fmt.Println(err)
				c.Close()
				return
			}

			connected = true
			remoteIP = c.RemoteAddr()
			//Here we should save this key
			//Then we should send our public key
			//TODO GUI: Ask if user accepts connection. If yes set status to: exchanging session keys
		}
	case HELLORESPONSE:
		if !connected {
			reader.Read(buffer)
			if err != nil {
				fmt.Println(err)
				c.Close()
				return
			}
			connected = true
			remoteIP = c.RemoteAddr()
			//Here we should save this key
			//Send session key and all connection properties using this public key back to client
			//TODO GUI: Change status to: exchanging session key
		}
	case CONNECTIONPROPERTIES:
		if connected {
			reader.Read(buffer)
			err = HandleConnectionProperties(buffer)
			if err != nil {
				fmt.Println(err)
				c.Close()
				return
			}
		}
	}

	c.Close()

}
