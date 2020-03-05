package main

import (
	"bytes"
	"encoding/binary"
)

var myPrivateKey []byte
var keySize int32
var blockSize int32
var cipherMode cipherblockmode
var iv []byte
var alghorytm byte
var publicKeyClient []byte

//HandleConnectionProperties decrypts connection properties using private key and sets all properties
//  Schema of frame
// |alghorytm byte|keysize int32|blocksize int32|ciphermode byte|publiceKey [keysize]byte|IV (if exists) [blocksize]byte|
//
func HandleConnectionProperties(props []byte) error {

	var decrypted []byte
	var err error

	if decrypted, err = DecryptRSA(props, myPrivateKey); err != nil {
		return err
	}

	buf := bytes.NewBuffer(decrypted)

	if err = binary.Read(buf, binary.LittleEndian, &alghorytm); err != nil {
		return err
	}

	if err = binary.Read(buf, binary.LittleEndian, &keySize); err != nil {
		return err
	}

	if err = binary.Read(buf, binary.LittleEndian, &blockSize); err != nil {
		return err
	}

	if err = binary.Read(buf, binary.LittleEndian, &cipherMode); err != nil {
		return err
	}

	publicKeyClient = make([]byte, keySize)

	if err = binary.Read(buf, binary.LittleEndian, publicKeyClient); err != nil {
		return err
	}

	iv = make([]byte, blockSize)

	if cipherMode == CBC || cipherMode == OFB || cipherMode == CFB {
		if err = binary.Read(buf, binary.LittleEndian, iv); err != nil {
			return err
		}
	}

	return nil
}
