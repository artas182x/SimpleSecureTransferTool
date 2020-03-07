package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const magicnumber uint32 = 0x1337ABCD
const bufsize = 8096

var endianness = binary.BigEndian

type packettype byte

//NetClient is structure representing netclient for receiving and sending tcp packets
type NetClient struct {
	listenport     int32
	connected      bool
	remoteIP       string
	messageHandler EncMess
}

// Structure representing packet types
const (
	//Client sends hello packet with public key
	HELLO = iota
	HELLORESPONSE
	CONNECTIONPROPERTIES
	TEXTMESSAGE
)

//NetClientInit initializes netclient with listen port number
func NetClientInit(listenPort int32, encMess EncMess) (netClient NetClient) {
	netClient.connected = false
	netClient.messageHandler = encMess
	netClient.listenport = listenPort
	return
}

//NetclientListen is main function for receiving connection. It's recommended to run it in separate thread
func (netClient *NetClient) NetclientListen() {
	connection, err := net.Listen("tcp", fmt.Sprintf(":%d", netClient.listenport))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Listening on port %d\n", netClient.listenport)
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

		if endianness.Uint32(magicbuffer) != magicnumber {
			c.Close()
			continue
		}

		if netClient.connected && strings.Split(c.RemoteAddr().String(), ":")[0] != strings.Split(netClient.remoteIP, ":")[0] {
			c.Close()
			continue
		}

		go netClient.handleIncomingConnection(c)

	}
}

func (netClient *NetClient) handleIncomingConnection(c net.Conn) {

	reader := bufio.NewReader(c)
	netData, err := reader.ReadByte()

	if err != nil {
		fmt.Println(err)
		return
	}

	buffer := make([]byte, bufsize)

	switch netData {
	case HELLO:
		if !netClient.connected {
			var port int32
			if err := binary.Read(reader, endianness, &port); err != nil {
				fmt.Println(err)
				c.Close()
				return
			}

			netClient.remoteIP = fmt.Sprintf("%s:%d", strings.Split(c.RemoteAddr().String(), ":")[0], port)

			_, err = reader.Read(buffer)

			if err != nil {
				fmt.Println(err)
				c.Close()
				return
			}

			err = netClient.messageHandler.HandleReceivedPublicKey(buffer)
			if err != nil {
				fmt.Println(err)
				c.Close()
			}

			netClient.connected = true

			fmt.Println("Received hello")

			if err := netClient.SendHelloResponse(); err != nil {
				fmt.Println(err)
				c.Close()
				return
			}

			//TODO GUI: Ask if user accepts connection. If yes set status to: exchanging session keys
		}
	case HELLORESPONSE:
		if !netClient.connected {
			var port int32
			if err := binary.Read(reader, endianness, &port); err != nil {
				fmt.Println(err)
				c.Close()
				return
			}

			netClient.remoteIP = fmt.Sprintf("%s:%d", strings.Split(c.RemoteAddr().String(), ":")[0], port)

			reader.Read(buffer)
			if err != nil {
				fmt.Println(err)
				c.Close()
				return
			}

			err = netClient.messageHandler.HandleReceivedPublicKey(buffer)
			if err != nil {
				fmt.Println(err)
				c.Close()
				return
			}

			fmt.Println("Received hello response")

			netClient.connected = true

			err = netClient.SendConnectionProperties()

			if err != nil {
				fmt.Println(err)
				c.Close()
				return
			}

			//TODO GUI: Change status to: exchanging session key
		}
	case CONNECTIONPROPERTIES:
		if netClient.connected {
			reader.Read(buffer)
			err = netClient.messageHandler.HandleConnectionProperties(buffer)
			if err != nil {
				fmt.Println(err)
				c.Close()
				return
			}

			fmt.Println("Received connection properties")
		}

	case TEXTMESSAGE:
		if netClient.connected {
			//	reader.Read(buffer)
			err = netClient.messageHandler.HandleTextMessage(reader)
			if err != nil {
				fmt.Println(err)
				c.Close()
				return
			}
		}
	}

	c.Write([]byte("OK"))
	c.Close()

}

func (netClient *NetClient) send(message []byte, ptype packettype, servAddr string) (response []byte, err error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", servAddr)

	if err != nil {
		return nil, err
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)

	binary.Write(buf, endianness, magicnumber)
	binary.Write(buf, endianness, ptype)
	binary.Write(buf, endianness, message)

	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return nil, err
	}

	bufferbyte := make([]byte, 2)
	conn.Read(bufferbyte)

	if string(bufferbyte) != "OK" {
		return nil, errors.New("Wrong response")
	}

	conn.Close()

	return bufferbyte, nil
}

//SendHello sends connection request along with public key
// Schema of frame
// |uint32 listenport|keySize int32|key [bits]byte|
func (netClient *NetClient) SendHello(servAddr string) error {

	toSend, err := netClient.messageHandler.GenerateHelloMessage(netClient.listenport)
	if err != nil {
		return err
	}

	_, err = netClient.send(toSend, HELLO, servAddr)

	if err != nil {
		return err
	}

	return nil

}

//SendHelloResponse sends connection request accept and public key
// Schema of frame
// |uint32 listenport|keySize int32|key [bits]byte|
func (netClient *NetClient) SendHelloResponse() error {

	toSend, err := netClient.messageHandler.GenerateHelloMessage(netClient.listenport)
	if err != nil {
		return err
	}

	_, err = netClient.send(toSend, HELLORESPONSE, netClient.remoteIP)

	if err != nil {
		return err
	}

	return nil

}

//SendConnectionProperties generates and sends client properties frame
func (netClient *NetClient) SendConnectionProperties() error {
	toSend, err := netClient.messageHandler.GenerateConnectionProperties()

	if err != nil {
		return err
	}

	_, err = netClient.send(toSend, CONNECTIONPROPERTIES, netClient.remoteIP)

	if err != nil {
		return err
	}

	return nil
}

//SendTextMessage send encrypted text message to other client
func (netClient *NetClient) SendTextMessage(origText string) error {
	toSend, err := netClient.messageHandler.GenerateTextMessage(origText)

	if err != nil {
		return err
	}

	_, err = netClient.send(toSend, TEXTMESSAGE, netClient.remoteIP)

	if err != nil {
		return err
	}

	return nil
}
