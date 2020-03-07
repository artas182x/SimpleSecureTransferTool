package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"
)

const rsaSize = 4096 / 8

//EncMess is structure used for encrypting and decrypting all messages going through TCP
type EncMess struct {
	//Needs to be read from file
	myPrivateKey []byte
	myPublicKey  []byte

	publicKeyClient []byte
	keySize         int32
	blockSize       int32
	iv              []byte
	//Not used yet
	alghorytm byte
	aesKey    []byte
	//When changed by GUI connection properties must be sent to second client
	cipherMode cipherblockmode
}

//EncryptedMessageHandler creates instance of encrypted message handler
func EncryptedMessageHandler(keySize int32, cipher cipherblockmode) (encMess EncMess) {
	encMess.keySize = keySize
	encMess.blockSize = aes.BlockSize
	encMess.cipherMode = cipher
	encMess.alghorytm = 0
	rand.Seed(time.Now().UTC().UnixNano())

	encMess.iv = make([]byte, encMess.blockSize)
	encMess.aesKey = make([]byte, encMess.keySize)
	encMess.generateRandomKeyandIV()

	return
}

//HandleConnectionProperties decrypts connection properties using private key and sets all properties
//  Schema of frame
// |alghorytm byte|keysize int32|blocksize int32|ciphermode byte|aesKey [keysize]byte|IV (if exists) [blocksize]byte|
//
func (encMess *EncMess) HandleConnectionProperties(props []byte) error {

	var decrypted []byte
	var err error

	if decrypted, err = DecryptRSA(props, encMess.myPrivateKey); err != nil {
		return err
	}

	buf := bytes.NewBuffer(decrypted)

	if err = binary.Read(buf, endianness, &encMess.alghorytm); err != nil {
		return err
	}

	if err = binary.Read(buf, endianness, &encMess.keySize); err != nil {
		return err
	}

	if err = binary.Read(buf, endianness, &encMess.blockSize); err != nil {
		return err
	}

	if err = binary.Read(buf, endianness, &encMess.cipherMode); err != nil {
		return err
	}

	encMess.aesKey = make([]byte, encMess.keySize)

	if err = binary.Read(buf, endianness, encMess.aesKey); err != nil {
		return err
	}

	encMess.iv = make([]byte, encMess.blockSize)

	if encMess.cipherMode == CBC || encMess.cipherMode == OFB || encMess.cipherMode == CFB {
		if err = binary.Read(buf, endianness, encMess.iv); err != nil {
			return err
		}
	}

	return nil
}

//HandleReceivedPublicKey is being executed when we receive client's public key
// Schema of frame
// |keySize int32|key [bits]byte|
func (encMess *EncMess) HandleReceivedPublicKey(key []byte) error {
	buf := bytes.NewBuffer(key)

	var bits int32
	var err error

	if err = binary.Read(buf, endianness, &bits); err != nil {
		return err
	}

	encMess.publicKeyClient = make([]byte, bits)

	if err = binary.Read(buf, endianness, encMess.publicKeyClient); err != nil {
		return err
	}

	return nil

}

//HandleTextMessage reader message from buffer and decrypts it
func (encMess *EncMess) HandleTextMessage(reader *bufio.Reader) error {

	var err error
	var decrypted string
	var size int32

	if err = binary.Read(reader, endianness, &size); err != nil {
		return err
	}

	var buf []byte = make([]byte, size)

	if err = binary.Read(reader, endianness, buf); err != nil {
		return err
	}

	if decrypted, err = DecryptTextMessage(encMess.aesKey, encMess.iv, buf, encMess.cipherMode); err != nil {
		return err
	}

	//TEST PRINTLN TODO GUI
	fmt.Printf("Received message: %s\n", decrypted)

	return nil

}

//GenerateHelloMessage generates hello message and rsa keypair
func (encMess *EncMess) GenerateHelloMessage(listenPort int32) (out []byte, err error) {

	buf := new(bytes.Buffer)

	binary.Write(buf, endianness, listenPort)
	binary.Write(buf, endianness, int32(cap(encMess.myPublicKey)))
	binary.Write(buf, endianness, encMess.myPublicKey)

	return buf.Bytes(), nil
}

//GenerateConnectionProperties generates encrypted connection properties frame using current settings
// Schema of frame
// |alghorytm byte|keysize int32|blocksize int32|ciphermode byte|aesKey [keysize]byte|IV (if exists) [blocksize]byte|
//
func (encMess *EncMess) GenerateConnectionProperties() ([]byte, error) {
	encMess.generateRandomKeyandIV()
	buf := new(bytes.Buffer)
	binary.Write(buf, endianness, encMess.alghorytm)
	binary.Write(buf, endianness, encMess.keySize)
	binary.Write(buf, endianness, encMess.blockSize)
	binary.Write(buf, endianness, encMess.cipherMode)
	binary.Write(buf, endianness, encMess.aesKey)

	if encMess.cipherMode == CBC || encMess.cipherMode == OFB || encMess.cipherMode == CFB {
		binary.Write(buf, endianness, encMess.iv)
	}

	out, err := EncryptRSA(buf.Bytes(), encMess.publicKeyClient)
	if err != nil {
		return nil, err
	}

	return out, nil
}

//GenerateTextMessage generates aes encrypted text byte array
func (encMess *EncMess) GenerateTextMessage(origText string) ([]byte, error) {
	encrypted, err := EncryptTextMessage(encMess.aesKey, encMess.iv, origText, encMess.cipherMode)

	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, endianness, int32(len(encrypted)))
	binary.Write(buf, endianness, encrypted)

	return buf.Bytes(), nil
}

//LoadKeys Don't generate everytime. Do it on first start and on permises by clicking on option in GUI
//TODO load public and private key from file in GUI
func (encMess *EncMess) LoadKeys() (err error) {

	if encMess.myPrivateKey, encMess.myPublicKey, err = GenerateKeyPair(rsaSize * 8); err != nil {
		return
	}

	return nil
}

func (encMess *EncMess) generateRandomKeyandIV() {
	encMess.iv = make([]byte, encMess.blockSize)
	encMess.aesKey = make([]byte, encMess.keySize)
	GenerateIV(encMess.iv)
	GenerateKey(encMess.aesKey)
}
