package main

import (
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func TestTextMessagesEncryptionECB(t *testing.T) {

	key, _ := hex.DecodeString("7368616e676520746869732070617373")
	msg := "Test string - testing encryption and decryption"
	var encrypted []byte
	var decrypted string
	var err error

	iv := make([]byte, aes.BlockSize)

	if err = GenerateIV(iv); err != nil {
		t.Error(err)
	}

	if encrypted, err = EncryptTextMessage(key, iv, msg, ECB); err != nil {
		t.Error(err)
	}

	if decrypted, err = DecryptTextMessage(key, iv, encrypted, ECB); err != nil {
		t.Error(err)
	}

	if msg != decrypted {
		t.Error("Original message and decrypted version does not match")
	}

	if msg == string(encrypted) {
		t.Error("Encrypted message and encrypted version should not be the same")
	}
}

func TestTextMessagesEncryptionCBC(t *testing.T) {

	key, _ := hex.DecodeString("7368616e676520746869732070617373")
	msg := "Test string - testing encryption and decryption"
	var encrypted []byte
	var decrypted string
	var err error

	iv := make([]byte, aes.BlockSize)

	if err = GenerateIV(iv); err != nil {
		t.Error(err)
	}

	if encrypted, err = EncryptTextMessage(key, iv, msg, CBC); err != nil {
		t.Error(err)
	}

	if decrypted, err = DecryptTextMessage(key, iv, encrypted, CBC); err != nil {
		t.Error(err)
	}

	if msg != decrypted {
		t.Error("Original message and decrypted version does not match")
	}

	if msg == string(encrypted) {
		t.Error("Encrypted message and encrypted version should not be the same")
	}
}

func TestTextMessagesEncryptionCFB(t *testing.T) {

	key, _ := hex.DecodeString("7368616e676520746869732070617373")
	msg := "Test string - testing encryption and decryption"
	var encrypted []byte
	var decrypted string
	var err error

	iv := make([]byte, aes.BlockSize)

	if err = GenerateIV(iv); err != nil {
		t.Error(err)
	}

	if encrypted, err = EncryptTextMessage(key, iv, msg, CFB); err != nil {
		t.Error(err)
	}

	if decrypted, err = DecryptTextMessage(key, iv, encrypted, CFB); err != nil {
		t.Error(err)
	}

	if msg != decrypted {
		t.Error("Original message and decrypted version does not match")
	}

	if msg == string(encrypted) {
		t.Error("Encrypted message and encrypted version should not be the same")
	}
}

func TestTextMessagesEncryptionOFB(t *testing.T) {

	key, _ := hex.DecodeString("7368616e676520746869732070617373")
	msg := "Test string - testing encryption and decryption"
	var encrypted []byte
	var decrypted string
	var err error

	iv := make([]byte, aes.BlockSize)

	if err = GenerateIV(iv); err != nil {
		t.Error(err)
	}

	if encrypted, err = EncryptTextMessage(key, iv, msg, OFB); err != nil {
		t.Error(err)
	}

	if decrypted, err = DecryptTextMessage(key, iv, encrypted, OFB); err != nil {
		t.Error(err)
	}

	if msg != decrypted {
		t.Error("Original message and decrypted version does not match")
	}

	if msg == string(encrypted) {
		t.Error("Encrypted message and encrypted version should not be the same")
	}
}
