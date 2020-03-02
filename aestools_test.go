package main

import (
	"encoding/hex"
	"testing"
)

func TestTextMessagesEncryptionECB(t *testing.T) {

	key, _ := hex.DecodeString("7368616e676520746869732070617373")
	msg := "Test string - testing encryption and decryption"
	var encrypted []byte
	var decrypted string
	var err error

	if encrypted, err = encryptTextMessage(key, msg, ECB); err != nil {
		t.Error(err)
	}

	t.Log("Encrypted ECB: " + hex.EncodeToString(encrypted))

	if decrypted, err = decryptTextMessage(key, encrypted, ECB); err != nil {
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

	if encrypted, err = encryptTextMessage(key, msg, CBC); err != nil {
		t.Error(err)
	}

	t.Log("Encrypted CBC: " + hex.EncodeToString(encrypted))

	if decrypted, err = decryptTextMessage(key, encrypted, CBC); err != nil {
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

	if encrypted, err = encryptTextMessage(key, msg, CFB); err != nil {
		t.Error(err)
	}

	t.Log("Encrypted CFB: " + hex.EncodeToString(encrypted))

	if decrypted, err = decryptTextMessage(key, encrypted, CFB); err != nil {
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

	if encrypted, err = encryptTextMessage(key, msg, OFB); err != nil {
		t.Error(err)
	}

	t.Log("Encrypted OFB: " + hex.EncodeToString(encrypted))

	if decrypted, err = decryptTextMessage(key, encrypted, OFB); err != nil {
		t.Error(err)
	}

	if msg != decrypted {
		t.Error("Original message and decrypted version does not match")
	}

	if msg == string(encrypted) {
		t.Error("Encrypted message and encrypted version should not be the same")
	}
}
