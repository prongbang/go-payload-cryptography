package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/prongbang/go-payload-cryptography/cryptox"
	"github.com/prongbang/go-payload-cryptography/loader"
)

func main() {
	fileLoader := loader.NewFileLoader()
	keyLoader := loader.NewPrivateKeyLoader(fileLoader)
	rsaCrypto := cryptox.NewRSACryptography()

	// Get key from file
	filename := "private-key.pem"
	passPhrase := "secret"
	privateKey, err := keyLoader.Load(filename, passPhrase)
	if err != nil {
		fmt.Println("Could not load private key from file", err)
		return
	}

	// Mock payload
	payload, _ := json.Marshal(map[string]string{
		"username": "userX",
		"password": "passX",
	})

	// Encrypt
	cipherText, _ := rsaCrypto.EncryptOAEP(&privateKey.PublicKey, payload)
	encrypted := base64.StdEncoding.EncodeToString(cipherText)
	fmt.Println("CipherText:", encrypted)

	// Decrypt
	encryptedByte, err := base64.StdEncoding.DecodeString(encrypted)
	plainText, _ := rsaCrypto.DecryptOAEP(privateKey, encryptedByte)
	fmt.Println("PlainText: ", string(plainText))
}
