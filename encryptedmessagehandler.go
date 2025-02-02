package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gotk3/gotk3/glib"
)

const rsaSize = 4096 / 8

//EncMess is structure used for encrypting and decrypting all messages going through TCP
type EncMess struct {
	//Needs to be read from file
	myPrivateKey []byte
	myPublicKey  []byte

	publicKeyClient []byte
	keySize         uint32
	blockSize       uint32
	iv              []byte
	//Not used yet
	alghorytm byte
	aesKey    []byte
	//When changed by GUI connection properties must be sent to second client
	cipherMode cipherblockmode
}

//EncryptedMessageHandler creates instance of encrypted message handler
func EncryptedMessageHandler(keySize uint32, cipher cipherblockmode) (encMess EncMess) {
	encMess.keySize = keySize
	encMess.blockSize = aes.BlockSize
	encMess.cipherMode = cipher
	encMess.alghorytm = 0
	rand.Seed(time.Now().UTC().UnixNano())

	//encMess.iv = make([]byte, encMess.blockSize)
	//encMess.aesKey = make([]byte, encMess.keySize)
	encMess.generateRandomKeyandIV()

	return
}

//HandleCipherMode decrypts cipher mode using privateKey
//  Schema of frame
// |ciphermode byte|
//
func (encMess *EncMess) HandleCipherMode(props []byte, app *GUIApp) error {

	var decrypted []byte
	var err error

	if decrypted, err = DecryptRSA(props, encMess.myPrivateKey); err != nil {
		encMess.cipherMode = 0
		if app.cipherChoiceBox != nil {
			glib.IdleAdd(func() {
				app.UpdateCipherMode()
			})
		}
		return nil
	}

	buf := bytes.NewBuffer(decrypted)

	if err = binary.Read(buf, endianness, &encMess.cipherMode); err != nil {
		return err
	}

	//Wrong cipher properties - assume defaults - don't throw error, it's project requirement
	if encMess.cipherMode > 4 {
		encMess.cipherMode = 0
	}

	if app.cipherChoiceBox != nil {
		glib.IdleAdd(func() {
			app.UpdateCipherMode()
		})
	}

	return nil
}

//HandleConnectionPropertiesResponse decrypts connection properties using private key and sets all properties
//  Schema of frame
// |aesKey [keysize]byte|IV [blocksize]byte|
//
func (encMess *EncMess) HandleConnectionPropertiesResponse(props []byte, app *GUIApp) error {

	var decrypted []byte
	var err error

	if decrypted, err = DecryptRSA(props, encMess.myPrivateKey); err != nil {
		if app.cipherChoiceBox != nil {
			glib.IdleAdd(func() {
				app.UpdateCipherMode()
			})
		}
		return nil
	}

	buf := bytes.NewBuffer(decrypted)

	aesKeyRv := make([]byte, encMess.keySize)

	if err = binary.Read(buf, endianness, aesKeyRv); err != nil {
		//	return err
	}

	ivRv := make([]byte, encMess.blockSize)

	if err = binary.Read(buf, endianness, ivRv); err != nil {
		//return err
	}

	//XORing our aes key and iv with received iv to improve security. Both clients are now responsible for generating these properties
	for i := 0; i < int(encMess.keySize); i++ {
		encMess.aesKey[i] ^= aesKeyRv[i]
	}

	for i := 0; i < int(encMess.blockSize); i++ {
		encMess.iv[i] ^= ivRv[i]
	}

	return nil
}

//HandleConnectionProperties decrypts connection properties using private key and sets all properties
//  Schema of frame
// |alghorytm byte|keysize int32|blocksize int32|ciphermode byte|aesKey [keysize]byte|IV [blocksize]byte|
//
func (encMess *EncMess) HandleConnectionProperties(props []byte, app *GUIApp) error {

	var decrypted []byte
	var err error

	if decrypted, err = DecryptRSA(props, encMess.myPrivateKey); err != nil {
		encMess.setDefaultConnectionParameters()
		if app.cipherChoiceBox != nil {
			glib.IdleAdd(func() {
				app.UpdateCipherMode()
			})
		}
		return nil
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
		//	return err
	}

	encMess.iv = make([]byte, encMess.blockSize)

	if err = binary.Read(buf, endianness, encMess.iv); err != nil {
		//return err
	}

	if encMess.cipherMode > 4 || encMess.blockSize%8 != 0 || encMess.keySize%8 != 0 {
		encMess.setDefaultConnectionParameters()
		if app.cipherChoiceBox != nil {
			glib.IdleAdd(func() {
				app.UpdateCipherMode()
			})
		}
	}

	return nil
}

func (encMess *EncMess) setDefaultConnectionParameters() {
	fmt.Println("Setting default connection parameters")
	encMess.keySize = 32
	encMess.blockSize = aes.BlockSize
	encMess.cipherMode = 0
	encMess.alghorytm = 0
	//encMess.iv = make([]byte, encMess.blockSize)
	//encMess.aesKey = make([]byte, encMess.keySize)
	//encMess.generateRandomKeyandIV()

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

	if err = binary.Read(buf, endianness, &encMess.publicKeyClient); err != nil {
		return err
	}

	encMess.generateRandomKeyandIV()

	return nil

}

//HandleTextMessage reader message from buffer and decrypts it
func (encMess *EncMess) HandleTextMessage(reader *bufio.Reader, app *GUIApp) error {

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

	if decrypted, err = DecryptTextMessage(encMess.aesKey, encMess.iv, buf, encMess.cipherMode, app); err != nil {
		return err
	}

	//TEST PRINTLN TODO GUI
	fmt.Printf("Received message: %s\n", decrypted)
	if app.messageTextIter != nil {
		suffix := ""
		if !strings.HasSuffix(decrypted, "\n") {
			suffix = "\n"
		}
		if utf8.ValidString(decrypted) {
			glib.IdleAdd(func() {
				app.ShowMessage(decrypted + suffix)
			})
		} else {
			glib.IdleAdd(func() {
				app.ShowMessage("(hex) " + hex.EncodeToString([]byte(decrypted)) + suffix)
			})
		}
	}
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

//GenerateCipherMode generates encrypted cipher mode frame using current settings
// Schema of frame
// |ciphermode byte|
//
func (encMess *EncMess) GenerateCipherMode() ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, endianness, encMess.cipherMode)

	out, err := EncryptRSA(buf.Bytes(), encMess.publicKeyClient)
	if err != nil {
		return nil, err
	}

	return out, nil
}

//GenerateConnectionProperties generates encrypted connection properties frame using current settings
// Schema of frame
// |alghorytm byte|keysize int32|blocksize int32|ciphermode byte|aesKey [keysize]byte|IV (if exists) [blocksize]byte|
//
func (encMess *EncMess) GenerateConnectionProperties() ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, endianness, encMess.alghorytm)
	binary.Write(buf, endianness, encMess.keySize)
	binary.Write(buf, endianness, encMess.blockSize)
	binary.Write(buf, endianness, encMess.cipherMode)
	binary.Write(buf, endianness, encMess.aesKey)

	binary.Write(buf, endianness, encMess.iv)

	out, err := EncryptRSA(buf.Bytes(), encMess.publicKeyClient)
	if err != nil {
		return nil, err
	}

	return out, nil
}

//GenerateConnectionPropertiesResponse generates encrypted connection properties response frame using current settings. Also it generates our
// factor of aes key and iv and XORs it with received key from second client for security
// Schema of frame
// |aesKey [keysize]byte|IV [blocksize]byte|
//
func (encMess *EncMess) GenerateConnectionPropertiesResponse() ([]byte, error) {
	buf := new(bytes.Buffer)

	iv2 := make([]byte, encMess.blockSize)
	aesKey2 := make([]byte, encMess.keySize)
	GenerateIV(iv2)
	GenerateKey(aesKey2)

	binary.Write(buf, endianness, aesKey2)
	binary.Write(buf, endianness, iv2)

	out, err := EncryptRSA(buf.Bytes(), encMess.publicKeyClient)
	if err != nil {
		return nil, err
	}

	//XORing our aes key and iv with received iv to improve security. Both clients are now responsible for generating these properties
	for i := 0; i < int(encMess.keySize); i++ {
		encMess.aesKey[i] ^= aesKey2[i]
	}

	for i := 0; i < int(encMess.blockSize); i++ {
		encMess.iv[i] ^= iv2[i]
	}

	return out, nil
}

//GenerateTextMessage generates aes encrypted text byte array
func (encMess *EncMess) GenerateTextMessage(origText string, app *GUIApp) ([]byte, error) {
	encrypted, err := EncryptTextMessage(encMess.aesKey, encMess.iv, origText, encMess.cipherMode, app)

	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, endianness, int32(len(encrypted)))
	binary.Write(buf, endianness, encrypted)

	return buf.Bytes(), nil
}

//LoadKeys load keys encrypted by AES-CBC using SHA-256 hash
//TODO load public and private key from file in GUI at app startup.  Don't throw error when password is incorrect
func (encMess *EncMess) LoadKeys(dir string, password string, app *GUIApp) (err error) {

	hash := sha256.Sum256([]byte(password))

	var privKeyEncrypted *os.File
	var pubKeyEncrypted *os.File

	var privKey = new(bytes.Buffer)
	var pubKey = new(bytes.Buffer)

	iv := make([]byte, aes.BlockSize)

	if privKeyEncrypted, err = os.Open(path.Join(dir, "privKey")); err != nil {
		return err
	}

	if pubKeyEncrypted, err = os.Open(path.Join(dir, "pubKey")); err != nil {
		return err
	}

	privKeyEncrypted.Read(iv)

	defer privKeyEncrypted.Close()

	if err = decryptCBC(hash[:], iv, privKeyEncrypted, privKey, app); err != nil {
		return err
	}

	defer pubKeyEncrypted.Close()

	if err = decryptCBC(hash[:], iv, pubKeyEncrypted, pubKey, app); err != nil {
		return err
	}

	encMess.myPrivateKey = privKey.Bytes()
	encMess.myPublicKey = pubKey.Bytes()

	return nil
}

//CreateKeys - creates public and private keypair in given directory. Both files encrypted by AES-CBC using SHA-256 hash
//TODO load create keys in GUI. If there are no key at first app startup they should be created
func (encMess *EncMess) CreateKeys(dir string, password string, app *GUIApp) (err error) {

	if encMess.myPrivateKey, encMess.myPublicKey, err = GenerateKeyPair(rsaSize * 8); err != nil {
		return
	}

	bReaderPriv := bytes.NewReader(encMess.myPrivateKey)
	bReaderPub := bytes.NewReader(encMess.myPublicKey)

	hash := sha256.Sum256([]byte(password))

	var privKeyEncrypted *os.File
	var pubKeyEncrypted *os.File

	if privKeyEncrypted, err = os.Create(path.Join(dir, "privKey")); err != nil {
		return err
	}

	if pubKeyEncrypted, err = os.Create(path.Join(dir, "pubKey")); err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	GenerateIV(iv)

	if _, err = privKeyEncrypted.Write(iv); err != nil {
		return err
	}

	defer privKeyEncrypted.Close()

	if err = encryptCBC(hash[:], iv, bReaderPriv, privKeyEncrypted, uint64(cap(encMess.myPrivateKey)), app); err != nil {
		return err
	}

	defer pubKeyEncrypted.Close()

	if err = encryptCBC(hash[:], iv, bReaderPub, pubKeyEncrypted, uint64(cap(encMess.myPublicKey)), app); err != nil {
		return err
	}

	return nil
}

func (encMess *EncMess) generateRandomKeyandIV() {
	encMess.iv = make([]byte, encMess.blockSize)
	encMess.aesKey = make([]byte, encMess.keySize)
	GenerateIV(encMess.iv)
	GenerateKey(encMess.aesKey)
}
