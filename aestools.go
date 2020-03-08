package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"os"

	"./aesciphers"
)

//cipherblockmode represents Cipher Block Mode used for encryption/decryption
type cipherblockmode byte

// Structure representing cipher block modes
const (
	ECB = iota
	CBC
	CFB
	OFB
)

//GenerateIV generates random IV - initialization vector with size of array. Assumes seed is initialized
func GenerateIV(iv []byte) (err error) {
	_, err = io.ReadFull(rand.Reader, iv)
	return
}

//GenerateKey generates random aes key with size of array. Assumes seed is initialized
func GenerateKey(key []byte) (err error) {
	_, err = io.ReadFull(rand.Reader, key)
	return
}

//Used for ECB and CBC ciphers only because they implement BlockMode interface
func encryptStream(mode cipher.BlockMode, reader io.Reader, writer io.Writer, size uint64) error {
	blockSize := mode.BlockSize() * 128

	//Write size at the beggining
	if err := binary.Write(writer, binary.BigEndian, size); err != nil {
		return err
	}

	buf := make([]byte, blockSize)
	for {
		_, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			} else if err == io.ErrUnexpectedEOF {
			} else {
				return err
			}
		}
		mode.CryptBlocks(buf, buf)
		if _, err = writer.Write(buf); err != nil {
			return err
		}

	}

	return nil
}

//Used for ECB and CBC ciphers only because they implement BlockMode interface
func decryptStream(mode cipher.BlockMode, reader io.Reader, writer io.Writer) error {

	var size uint64
	var readBytes uint64
	blockSize := mode.BlockSize() * 128

	//Read size at the beggining
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return err
	}

	buf := make([]byte, blockSize)
	for {
		_, err := io.ReadFull(reader, buf)
		if err != nil {
			if err == io.EOF {
				if readBytes != size {
					return err
				}
				break
			} else {
				return err
			}
		}
		mode.CryptBlocks(buf, buf)

		readBytes += uint64(blockSize)
		if readBytes > size {
			diff := uint64(blockSize) - (readBytes - size)
			buf2 := buf[:diff]
			if _, err = writer.Write(buf2); err != nil {
				return err
			}
			readBytes -= diff
			break
		}

		if _, err = writer.Write(buf); err != nil {
			return err
		}

	}
	return nil
}

func encryptCFB(key []byte, iv []byte, bReader io.Reader, out io.Writer) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv[:])

	writer := &cipher.StreamWriter{S: stream, W: out}

	// Copy the input to the output buffer, encrypting as we go.
	if _, err := io.Copy(writer, bReader); err != nil {
		panic(err)
	}

	return
}

func encryptCBC(key []byte, iv []byte, bReader io.Reader, out io.Writer, size uint64) (err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := cipher.NewCBCEncrypter(block, iv[:])

	encryptStream(mode, bReader, out, size)

	return
}

func encryptECB(key []byte, bReader io.Reader, out io.Writer, size uint64) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := aesciphers.NewECBEncrypter(block)
	encryptStream(mode, bReader, out, size)

	return
}

func encryptOFB(key []byte, iv []byte, bReader io.Reader, out io.Writer) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	stream := cipher.NewOFB(block, iv[:])

	writer := &cipher.StreamWriter{S: stream, W: out}

	// Copy the input to the output buffer, encrypting as we go.
	if _, err := io.Copy(writer, bReader); err != nil {
		panic(err)
	}

	return
}

func decryptCFB(key []byte, iv []byte, bReader io.Reader, out io.Writer) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	stream := cipher.NewCFBDecrypter(block, iv[:])

	writer := &cipher.StreamWriter{S: stream, W: out}
	// Copy the input to the output buffer, encrypting as we go.
	if _, err := io.Copy(writer, bReader); err != nil {
		panic(err)
	}

	return
}

func decryptCBC(key []byte, iv []byte, bReader io.Reader, out io.Writer) (err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := cipher.NewCBCDecrypter(block, iv[:])

	err = decryptStream(mode, bReader, out)

	if err != nil {
		return err
	}

	return
}

func decryptECB(key []byte, bReader io.Reader, out io.Writer) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := aesciphers.NewECBDecrypter(block)
	err = decryptStream(mode, bReader, out)

	if err != nil {
		return err
	}

	return
}

func decryptOFB(key []byte, iv []byte, bReader io.Reader, out io.Writer) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	stream := cipher.NewOFB(block, iv[:])

	writer := &cipher.StreamWriter{S: stream, W: out}
	// Copy the input to the output buffer, encrypting as we go.
	if _, err := io.Copy(writer, bReader); err != nil {
		panic(err)
	}

	return
}

//EncryptTextMessage encrypts given string using given key. It takes key, message string and cipher block mode as arguument. As a result byte array is produced
func EncryptTextMessage(key []byte, iv []byte, message string, cipherblockmode cipherblockmode) (result []byte, err error) {

	bMessage := []byte(message)
	bReader := bytes.NewReader(bMessage)
	var b bytes.Buffer

	switch cipherblockmode {
	case CBC:
		err = encryptCBC(key, iv, bReader, io.Writer(&b), uint64(len(bMessage)))
		result = b.Bytes()
	case CFB:
		err = encryptCFB(key, iv, bReader, io.Writer(&b))
		result = b.Bytes()
	case OFB:
		err = encryptOFB(key, iv, bReader, io.Writer(&b))
		result = b.Bytes()
	case ECB:
		err = encryptECB(key, bReader, io.Writer(&b), uint64(len(bMessage)))
		result = b.Bytes()
	}

	if err != nil {
		return nil, err
	}

	return
}

//DecryptTextMessage decrypts given bytes to readable string. It takes key, input byte array and cipher block mode as argument. As a result output string is produced.
func DecryptTextMessage(key []byte, iv []byte, message []byte, cipherblockmode cipherblockmode) (result string, err error) {

	bReader := bytes.NewReader([]byte(message))
	var b bytes.Buffer

	switch cipherblockmode {
	case CBC:
		err = decryptCBC(key, iv, bReader, io.Writer(&b))
	case CFB:
		err = decryptCFB(key, iv, bReader, io.Writer(&b))
	case OFB:
		err = decryptOFB(key, iv, bReader, io.Writer(&b))
	case ECB:
		err = decryptECB(key, bReader, io.Writer(&b))
	}

	if err != nil {
		return "", err
	}

	result = string(b.Bytes())

	return
}

//EncryptFile encrypts file using given key. It takes key, os.File (twice as input and output) and cipher block mode as argument.
func EncryptFile(key []byte, iv []byte, input *os.File, output *os.File, cipherblockmode cipherblockmode) (err error) {
	fi, err := input.Stat()
	if err != nil {
		return
	}

	switch cipherblockmode {
	case CBC:
		err = encryptCBC(key, iv, input, output, uint64(fi.Size()))
	case CFB:
		err = encryptCFB(key, iv, input, output)
	case OFB:
		err = encryptOFB(key, iv, input, output)
	case ECB:
		err = encryptECB(key, input, output, uint64(fi.Size()))
	}

	if err != nil {
		return err
	}

	return
}

//DecryptFile decrypts file using given key. It takes key, os.File (twice as input and output) and cipher block mode as argument.
func DecryptFile(key []byte, iv []byte, input *os.File, output *os.File, cipherblockmode cipherblockmode) (err error) {
	switch cipherblockmode {
	case CBC:
		err = decryptCBC(key, iv, input, output)
	case CFB:
		err = decryptCFB(key, iv, input, output)
	case OFB:
		err = decryptOFB(key, iv, input, output)
	case ECB:
		err = decryptECB(key, input, output)
	}

	if err != nil {
		return err
	}

	return
}
