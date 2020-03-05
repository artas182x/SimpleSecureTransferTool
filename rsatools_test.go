package main

import (
	"bytes"
	"testing"
)

func TestRSAEncryption(t *testing.T) {
	privKey, pubkey, err := GenerateKeyPair(4096)

	if err != nil {
		t.Error(err)
	}

	testbyte := []byte("Test text to encrypt")

	result, err := EncryptRSA(testbyte, pubkey)

	if err != nil {
		t.Error(err)
	}

	decrypted, err := DecryptRSA(result, privKey)

	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(decrypted, testbyte) != 0 {
		t.Errorf("Decrypted text is not the same as input")
	}
}

func TestRandomness(t *testing.T) {
	testbyte := []byte("Test text to encrypt")

	_, pubkey, err := GenerateKeyPair(4096)

	if err != nil {
		t.Error(err)
	}

	result, err := EncryptRSA(testbyte, pubkey)

	if err != nil {
		t.Error(err)
	}

	result2, err := EncryptRSA(testbyte, pubkey)

	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(result, result2) == 0 {
		t.Errorf("Encrypted bytes twice should not give the same result")
	}

}

func TestKeysRandomness(t *testing.T) {
	privkey, pubkey, err := GenerateKeyPair(4096)

	if err != nil {
		t.Error(err)
	}

	privkey2, pubkey2, err := GenerateKeyPair(4096)

	if err != nil {
		t.Error(err)
	}

	if bytes.Compare(pubkey, pubkey2) == 0 {
		t.Errorf("Generated pubKeys twice should not be the same")
	}

	if bytes.Compare(privkey, privkey2) == 0 {
		t.Errorf("Generated pubKeys twice should not be the same")
	}

}
