package main

import (
	"./remotes/aesciphers"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"github.com/mitchellh/ioprogress"
	"io"
	"os"
	"time"
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
func encryptStream(mode cipher.BlockMode, reader io.Reader, writer io.Writer, size uint64, app *GUIApp) error {
	blockSize := mode.BlockSize() * 128

	//Write size at the beggining
	if err := binary.Write(writer, binary.BigEndian, size); err != nil {
		return err
	}
	alreadyRead := 0
	timeStart := time.Now()
	buf := make([]byte, blockSize)
	for {
		nowRead, err := reader.Read(buf)
		alreadyRead += nowRead
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
		value := float64(alreadyRead) / float64(size)
		duration := time.Now().Sub(timeStart).String()
		app.UpdateEncryptionProgress(value, duration)
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

func encryptCFB(key []byte, iv []byte, bReader io.Reader, out io.Writer, size uint64, app *GUIApp) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	startTime := time.Now()
	updateProgress := func() ioprogress.DrawFunc {
		foo := func(progress, total int64) error {
			value := float64(progress) / float64(total)
			duration := time.Now().Sub(startTime).String()
			app.UpdateEncryptionProgress(value, duration)
			return nil
		}
		return foo
	}
	progressReader := &ioprogress.Reader{
		Reader:   bReader,
		Size:     int64(size),
		DrawFunc: updateProgress(),
	}

	stream := cipher.NewCFBEncrypter(block, iv[:])

	writer := &cipher.StreamWriter{S: stream, W: out}

	// Copy the input to the output buffer, encrypting as we go.
	if app.encryptProgressBar != nil {
		if _, err := io.Copy(writer, progressReader); err != nil {
			panic(err)
		}
	} else {
		if _, err := io.Copy(writer, bReader); err != nil {
			panic(err)
		}
	}

	return
}

func encryptCBC(key []byte, iv []byte, bReader io.Reader, out io.Writer, size uint64, app *GUIApp) (err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := cipher.NewCBCEncrypter(block, iv[:])

	encryptStream(mode, bReader, out, size, app)

	return
}

func encryptECB(key []byte, bReader io.Reader, out io.Writer, size uint64, app *GUIApp) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	mode := aesciphers.NewECBEncrypter(block)
	encryptStream(mode, bReader, out, size, app)

	return
}

func encryptOFB(key []byte, iv []byte, bReader io.Reader, out io.Writer, size uint64, app *GUIApp) (err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	startTime := time.Now()
	updateProgress := func() ioprogress.DrawFunc {
		foo := func(progress, total int64) error {
			value := float64(progress / total)
			duration := time.Now().Sub(startTime).String()
			app.UpdateEncryptionProgress(value, duration)
			return nil
		}
		return foo
	}
	progressReader := &ioprogress.Reader{
		Reader:   bReader,
		Size:     int64(size),
		DrawFunc: updateProgress(),
	}

	stream := cipher.NewOFB(block, iv[:])

	writer := &cipher.StreamWriter{S: stream, W: out}

	// Copy the input to the output buffer, encrypting as we go.
	if app.encryptProgressBar != nil {
		if _, err := io.Copy(writer, progressReader); err != nil {
			panic(err)
		}
	} else {
		if _, err := io.Copy(writer, bReader); err != nil {
			panic(err)
		}
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
func EncryptTextMessage(key []byte, iv []byte, message string, cipherblockmode cipherblockmode, app *GUIApp) (result []byte, err error) {

	bMessage := []byte(message)
	bReader := bytes.NewReader(bMessage)
	var b bytes.Buffer

	switch cipherblockmode {
	case CBC:
		err = encryptCBC(key, iv, bReader, io.Writer(&b), uint64(len(bMessage)), app)
		result = b.Bytes()
	case CFB:
		err = encryptCFB(key, iv, bReader, io.Writer(&b), uint64(len(bMessage)), app)
		result = b.Bytes()
	case OFB:
		err = encryptOFB(key, iv, bReader, io.Writer(&b), uint64(len(bMessage)), app)
		result = b.Bytes()
	case ECB:
		err = encryptECB(key, bReader, io.Writer(&b), uint64(len(bMessage)), app)
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
func EncryptFile(key []byte, iv []byte, input *os.File, output *os.File, cipherblockmode cipherblockmode, app *GUIApp) (err error) {
	fi, err := input.Stat()
	if err != nil {
		return
	}

	switch cipherblockmode {
	case CBC:
		err = encryptCBC(key, iv, input, output, uint64(fi.Size()), app)
	case CFB:
		err = encryptCFB(key, iv, input, output, uint64(fi.Size()), app)
	case OFB:
		err = encryptOFB(key, iv, input, output, uint64(fi.Size()), app)
	case ECB:
		err = encryptECB(key, input, output, uint64(fi.Size()), app)
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
