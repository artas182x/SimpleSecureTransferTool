package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
)

//cipherblockmode represents Cipher Block Mode used for encryption/decryption
type cipherblockmode int

// Structure representing cipher block modes
const (
	ECB = iota
	CBC
	CFB
	OFB
)

// IV - initialization vector
func generateIV(iv []byte) (err error) {
	_, err = io.ReadFull(rand.Reader, iv)
	return
}

//Used for ECB and CBC ciphers only because they implement BlockMode interface
func encryptStream(mode cipher.BlockMode, reader io.Reader, writer io.Writer, size uint64) error {
	blockSize := mode.BlockSize()

	//Write size at the beggining
	if err := binary.Write(writer, binary.LittleEndian, size); err != nil {
		return err
	}

	for {
		buf := make([]byte, blockSize)
		_, err := io.ReadFull(reader, buf)
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
	blockSize := mode.BlockSize()

	//Read size at the beggining
	if err := binary.Read(reader, binary.LittleEndian, &size); err != nil {
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

func encryptCFB(key []byte, bReader io.Reader, out io.Writer) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//Put IV at the beggining of encrypted files
	iv := make([]byte, block.BlockSize())
	err = generateIV(iv[:])
	if err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv[:])

	writer := &cipher.StreamWriter{S: stream, W: out}
	writer.W.Write(iv)
	// Copy the input to the output buffer, encrypting as we go.
	if _, err := io.Copy(writer, bReader); err != nil {
		panic(err)
	}

	return
}

func encryptCBC(key []byte, bReader io.Reader, out io.Writer, size uint64) (err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//Put IV at the beggining of encrypted files
	iv := make([]byte, block.BlockSize())
	err = generateIV(iv[:])
	if err != nil {
		return
	}

	mode := cipher.NewCBCEncrypter(block, iv[:])

	// Append IV at the beggining of file and encrypt stream
	out.Write(iv)
	encryptStream(mode, bReader, out, size)

	return
}

func encryptECB(key []byte, bReader io.Reader, out io.Writer, size uint64) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := NewECBEncrypter(block)
	encryptStream(mode, bReader, out, size)

	return
}

func encryptOFB(key []byte, bReader io.Reader, out io.Writer) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//Put IV at the beggining of encrypted files
	iv := make([]byte, block.BlockSize())
	err = generateIV(iv[:])
	if err != nil {
		return
	}

	stream := cipher.NewOFB(block, iv[:])

	writer := &cipher.StreamWriter{S: stream, W: out}

	// Append IV at the beggining of file
	writer.W.Write(iv)

	// Copy the input to the output buffer, encrypting as we go.
	if _, err := io.Copy(writer, bReader); err != nil {
		panic(err)
	}

	return
}

func decryptCFB(key []byte, bReader io.Reader, out io.Writer) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//Put IV at the beggining of encrypted files
	iv := make([]byte, block.BlockSize())
	_, err = io.ReadFull(bReader, iv)
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

func decryptCBC(key []byte, bReader io.Reader, out io.Writer) (err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//Put IV at the beggining of encrypted files
	iv := make([]byte, block.BlockSize())
	_, err = io.ReadFull(bReader, iv)
	if err != nil {
		return
	}

	mode := cipher.NewCBCDecrypter(block, iv[:])

	// Append IV at the beggining of file and encrypt stream
	decryptStream(mode, bReader, out)

	return
}

func decryptECB(key []byte, bReader io.Reader, out io.Writer) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := NewECBDecrypter(block)
	decryptStream(mode, bReader, out)

	return
}

func decryptOFB(key []byte, bReader io.Reader, out io.Writer) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//Put IV at the beggining of encrypted files
	iv := make([]byte, block.BlockSize())
	_, err = io.ReadFull(bReader, iv)
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
func EncryptTextMessage(key []byte, message string, cipherblockmode cipherblockmode) (result []byte, err error) {

	bMessage := []byte(message)
	bReader := bytes.NewReader(bMessage)
	var b bytes.Buffer

	switch cipherblockmode {
	case CBC:
		err = encryptCBC(key, bReader, io.Writer(&b), uint64(len(bMessage)))
		result = b.Bytes()
	case CFB:
		err = encryptCFB(key, bReader, io.Writer(&b))
		result = b.Bytes()
	case OFB:
		err = encryptOFB(key, bReader, io.Writer(&b))
		result = b.Bytes()
	case ECB:
		err = encryptECB(key, bReader, io.Writer(&b), uint64(len(bMessage)))
		result = b.Bytes()
	}

	return
}

//DecryptTextMessage decrypts given bytes to readable string. It takes key, input byte array and cipher block mode as argument. As a result output string is produced.
func DecryptTextMessage(key []byte, message []byte, cipherblockmode cipherblockmode) (result string, err error) {

	bReader := bytes.NewReader([]byte(message))
	var b bytes.Buffer

	switch cipherblockmode {
	case CBC:
		err = decryptCBC(key, bReader, io.Writer(&b))
	case CFB:
		err = decryptCFB(key, bReader, io.Writer(&b))
	case OFB:
		err = decryptOFB(key, bReader, io.Writer(&b))
	case ECB:
		err = decryptECB(key, bReader, io.Writer(&b))
	}

	result = string(b.Bytes())
	return
}
