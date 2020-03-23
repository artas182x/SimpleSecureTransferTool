package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const magicnumber uint32 = 0x1337ABCD
const bufsize = 8096

var endianness = binary.BigEndian

type packettype byte

//NetClient is structure representing netClient for receiving and sending tcp packets
type NetClient struct {
	listenport     int32
	connected      bool
	remoteIP       string
	messageHandler EncMess
	receiveDir     string
}

// Structure representing packet types
const (
	//Client sends hello packet with public key
	HELLO = iota
	HELLORESPONSE
	CONNECTIONPROPERTIES
	TEXTMESSAGE
	FILE
	PING
)

//NetClientInit initializes netClient with listen port number
func NetClientInit(listenPort int32, encMess EncMess) (netClient NetClient) {
	netClient.SetClientState(false)
	netClient.messageHandler = encMess
	netClient.listenport = listenPort
	netClient.receiveDir = "./files/"
	return
}

//SetCipher sets cipher
func (netClient *NetClient) SetCipher(cipher cipherblockmode) {
	netClient.messageHandler.cipherMode = cipher
}

//GetCipher gets cipher
func (netClient *NetClient) GetCipher() cipherblockmode {
	return netClient.messageHandler.cipherMode
}

//NetClientListen is main function for receiving connection. It's recommended to run it in separate thread
func (netClient *NetClient) NetClientListen(app *GUIApp) {
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

		go netClient.handleIncomingConnection(c, app)

	}
}

func (netClient *NetClient) handleIncomingConnection(c net.Conn, app *GUIApp) {

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

			netClient.SetClientState(true)

			hash := sha256.Sum256(netClient.messageHandler.publicKeyClient)

			fmt.Printf("Received hello from: IP: %s PubKey Hash: %s\n", netClient.remoteIP, hex.EncodeToString(hash[:]))
			app.SetConnected(true)
			app.ChangeAddress(netClient.remoteIP)
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

			netClient.SetClientState(true)

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
			err = netClient.messageHandler.HandleConnectionProperties(buffer, app)
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
			err = netClient.messageHandler.HandleTextMessage(reader, app)
			if err != nil {
				fmt.Println(err)
				c.Close()
				return
			}
		}
	case FILE:
		if netClient.connected {
			err = netClient.ReceiveFile(reader)
			if err != nil {
				fmt.Println(err)
				c.Close()
				return
			}
		}
	case PING:
		if netClient.connected {
			c.Write([]byte("OK"))
		} else {
			c.Write([]byte("NK"))
		}
		c.Close()
		return
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
	if message != nil {
		binary.Write(buf, endianness, message)
	}

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

//ReceiveFile decrypts received file using AES
func (netClient *NetClient) ReceiveFile(reader *bufio.Reader) error {
	bufferFileName := make([]byte, 64)
	bufferFileSize := make([]byte, 10)

	reader.Read(bufferFileSize)
	fileSize, _ := strconv.ParseInt(strings.Trim(string(bufferFileSize), ":"), 10, 64)

	reader.Read(bufferFileName)
	fileName := strings.Trim(string(bufferFileName), ":")

	newFile, err := os.Create(fileName + ".encrypted")

	if err != nil {
		return err
	}
	var receivedBytes int64

	for {
		if (fileSize - receivedBytes) < bufsize {
			io.CopyN(newFile, reader, (fileSize - receivedBytes))
			reader.Read(make([]byte, (receivedBytes+bufsize)-fileSize))
			break
		}
		io.CopyN(newFile, reader, bufsize)
		receivedBytes += bufsize

		fmt.Printf("Downloading file: %f\n", float64(receivedBytes)/float64(fileSize)*100)
	}

	newFileDecrypted, err := os.Create(path.Join(netClient.receiveDir, fileName))

	if err != nil {
		return err
	}

	newFile.Close()

	newFile, err = os.Open(fileName + ".encrypted")

	if err != nil {
		return err
	}

	fmt.Println("Decrypting file...")

	if err := DecryptFile(netClient.messageHandler.aesKey, netClient.messageHandler.iv, newFile,
		newFileDecrypted, netClient.messageHandler.cipherMode); err != nil {
		return err
	}

	newFile.Close()
	newFileDecrypted.Close()

	os.Remove(fileName + ".encrypted")

	fmt.Println("Decrypted successfully")

	return nil
}

//SendFile sends encrypted file using AES
func (netClient *NetClient) SendFile(file *os.File, app *GUIApp) error {
	randFileName := randString(10)
	var fileEncrypted *os.File
	var err error

	if fileEncrypted, err = os.Create(randFileName); err != nil {
		return err
	}

	if err := EncryptFile(netClient.messageHandler.aesKey, netClient.messageHandler.iv, file,
		fileEncrypted, netClient.messageHandler.cipherMode); err != nil {
		return err
	}

	fileEncrypted.Close()

	tcpAddr, err := net.ResolveTCPAddr("tcp", netClient.remoteIP)

	if err != nil {
		return err
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return err
	}

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	fileEncrypted, err = os.Open(randFileName)
	if err != nil {
		return err
	}

	stat2, err := fileEncrypted.Stat()
	if err != nil {
		return err
	}

	fileSize := fillString(strconv.FormatInt(stat2.Size(), 10), 10)
	fileName := fillString(stat.Name(), 64)

	buf := new(bytes.Buffer)

	binary.Write(buf, endianness, magicnumber)
	binary.Write(buf, endianness, packettype(FILE))

	conn.Write(buf.Bytes())
	conn.Write([]byte(fileSize))
	conn.Write([]byte(fileName))

	sendBuffer := make([]byte, bufsize)
	sendBytes := 0
	startTime := time.Now()
	for {
		read, err := fileEncrypted.Read(sendBuffer)
		sendBytes += read
		if err == io.EOF {
			break
		}

		fmt.Printf("Uploading file: %f\n", float64(sendBytes)/float64(stat2.Size())*100)
		duration := time.Now().Sub(startTime)
		println(duration.String())
		app.UpdateUploadProgress(float64(sendBytes)/float64(stat2.Size()), duration.String())
		conn.Write(sendBuffer)
	}

	bufferbyte := make([]byte, 2)
	conn.Read(bufferbyte)

	if string(bufferbyte) != "OK" {
		return errors.New("Wrong response")
	}

	conn.Close()

	fileEncrypted.Close()
	os.Remove(randFileName)

	return nil

}

//StartPinging sends Ping message every 2 seconds to check if client is still connected
func (netClient *NetClient) StartPinging(app *GUIApp) {
	for {
		time.Sleep(2 * time.Second)
		connected := netClient.Ping()
		if !connected {
			app.SetConnected(false)
			app.netClient.connected = false
			break
		}
	}
}

//Ping check if client is available. Return true if yes available
//TODO GUI notify if client disconnects
func (netClient *NetClient) Ping() bool {
	response, err := netClient.send(nil, PING, netClient.remoteIP)
	if err != nil {
		return false
	}
	if string(response) == "OK" {
		return true
	}
	return false
}

//SetClientState sets if client is connected ot not
//TODO In gui. Set text and buttons based on this state
func (netClient *NetClient) SetClientState(connected bool) {
	netClient.connected = connected
}
