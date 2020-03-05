package main

import (
	"crypto/rand"
	"crypto/sha512"

	"./pem"

	"./x509"

	"./rsa"
)

//GenerateKeyPair is used for generating private and public key
func GenerateKeyPair(bits int) ([]byte, []byte, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return exportPrivateKey(privkey), exportPublicKey(&privkey.PublicKey), err
}

//EncryptRSA encrypts byte array using public key
func EncryptRSA(data []byte, pubKey []byte) (out []byte, err error) {
	pubKeyImported, err := importPublicKey(pubKey)
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

//DecryptRSA decrypts byte array using public key
func DecryptRSA(data []byte, privKey []byte) (out []byte, err error) {
	privKeyImported, err := importPrivateKey(privKey)
	hash := sha512.New()
	out, err = rsa.DecryptOAEP(hash, rand.Reader, privKeyImported, importMsg(data), nil)
	if err != nil {
		return
	}
	return
}

//exportPublicKey is used to export public key in friendly format (PCKS1-encoded )
func exportPublicKey(pubkey *rsa.PublicKey) []byte {
	pubkeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pubkey)})
	return pubkeyPem
}

//exportPrivateKey is used to export public key in friendly format (PCKS1-encoded)
func exportPrivateKey(privatekey *rsa.PrivateKey) []byte {
	privatekeyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privatekey)})
	return privatekeyPem
}

//importPrivateKey is used to import PCKS1 encoded private key
func importPrivateKey(privKey []byte) (*rsa.PrivateKey, error) {
	privKeyImported, rest := pem.Decode(privKey)
	if privKeyImported == nil {
		return x509.ParsePKCS1PrivateKey(rest)
	}
	return x509.ParsePKCS1PrivateKey(privKeyImported.Bytes)
}

//importPublicKey is used to import PCKS1 encoded public key
func importPublicKey(pubKey []byte) (*rsa.PublicKey, error) {
	pubKeyImported, rest := pem.Decode(pubKey)
	if pubKeyImported == nil {
		return x509.ParsePKCS1PublicKey(rest)
	}
	return x509.ParsePKCS1PublicKey(pubKeyImported.Bytes)

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
