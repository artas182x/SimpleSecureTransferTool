package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/pem"

	"./x509"

	"./rsa"
)

//GenerateKeyPair is used for generating private and public key
func GenerateKeyPair(bits int) ([]byte, []byte, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return ExportPrivateKey(privkey), ExportPublicKey(&privkey.PublicKey), err
}

//EncryptData encrypts byte array using public key
func EncryptData(data []byte, pubKey []byte) (out []byte, err error) {
	pubKeyImported, err := ImportPublicKey(pubKey)
	if err != nil {
		return
	}
	hash := sha512.New()
	out, err = rsa.EncryptOAEP(hash, rand.Reader, pubKeyImported, data, nil)
	if err != nil {
		return
	}
	out = exportMsg(out)
	return
}

//DecryptData decrypts byte array using public key
func DecryptData(data []byte, privKey []byte) (out []byte, err error) {
	privKeyImported, err := ImportPrivateKey(privKey)
	hash := sha512.New()
	out, err = rsa.DecryptOAEP(hash, rand.Reader, privKeyImported, importMsg(data), nil)
	if err != nil {
		return
	}
	return
}

//ExportPublicKey is used to export public key in friendly format (PCKS1-encoded )
func ExportPublicKey(pubkey *rsa.PublicKey) []byte {
	pubkeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pubkey)})
	return pubkeyPem
}

//ExportPrivateKey is used to export public key in friendly format (PCKS1-encoded)
func ExportPrivateKey(privatekey *rsa.PrivateKey) []byte {
	privatekeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)})
	return privatekeyPem
}

//ImportPrivateKey is used to import PCKS1 encoded private key
func ImportPrivateKey(privKey []byte) (*rsa.PrivateKey, error) {
	privKeyImported, _ := pem.Decode(privKey)
	if privKeyImported != nil {
		return x509.ParsePKCS1PrivateKey(privKeyImported.Bytes)
	} else {
		blankPriv, _, _ := GenerateKeyPair(4096)
		return ImportPrivateKey(blankPriv)
	}
}

//ImportPublicKey is used to import PCKS1 encoded public key
func ImportPublicKey(pubKey []byte) (*rsa.PublicKey, error) {
	pubKeyImported, _ := pem.Decode(pubKey)
	if pubKeyImported != nil {
		return x509.ParsePKCS1PublicKey(pubKeyImported.Bytes)
	} else {
		_, pubBlank, _ := GenerateKeyPair(4096)
		return ImportPublicKey(pubBlank)
	}

}

//exportMsg is used to export already encrypted message in friendly format (PEM-encoded )
func exportMsg(msg []byte) []byte {
	msgPem := pem.EncodeToMemory(&pem.Block{Type: "MESSAGE", Bytes: msg})
	return msgPem
}

func importMsg(msg []byte) []byte {
	msgImported, _ := pem.Decode(msg)
	return msgImported.Bytes
}
