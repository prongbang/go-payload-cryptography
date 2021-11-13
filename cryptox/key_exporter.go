package cryptox

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

type KeyExporter interface {
	SaveToFile(keyPem string, filename string) error
	ReadFromFile(filename string) []byte
	PublicKeyToPEMString(pubkey *rsa.PublicKey) string
	PrivateKeyToPEMString(privateKey *rsa.PrivateKey) string
	PEMStringToPrivateKey(privateKeyPem []byte) *rsa.PrivateKey
	PEMStringToPublicKey(publicKeyPem []byte) *rsa.PublicKey
}

type keyExporter struct {
}

func (e *keyExporter) SaveToFile(keyPem string, filename string) error {
	pemBytes := []byte(keyPem)
	return ioutil.WriteFile(filename, pemBytes, 0400)
}

func (e *keyExporter) ReadFromFile(filename string) []byte {
	key, _ := ioutil.ReadFile(filename)
	return key
}

func (e *keyExporter) PEMStringToPrivateKey(privateKeyPem []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(privateKeyPem)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key
}

func (e *keyExporter) PEMStringToPublicKey(publicKeyPem []byte) *rsa.PublicKey {
	block, _ := pem.Decode(publicKeyPem)
	key, _ := x509.ParsePKCS1PublicKey(block.Bytes)
	return key
}

func (e *keyExporter) PrivateKeyToPEMString(privateKey *rsa.PrivateKey) string {
	privateKeyPem := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	))
	return privateKeyPem
}

func (e *keyExporter) PublicKeyToPEMString(pubkey *rsa.PublicKey) string {
	pubKeyPem := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pubkey),
		},
	))
	return pubKeyPem
}

func NewKeyExporter() KeyExporter {
	return &keyExporter{}
}
