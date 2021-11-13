package cryptox

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// RSACryptography
//
// OAEP this ensures that encoding the same message twice will not result in the same encrypted message
// https://ichi.pro/th/khumux-kar-khea-rhas-rsa-ni-go-28694008034141
//
type RSACryptography interface {
	GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey)

	Decrypt(privateKey *rsa.PrivateKey, cipherText []byte) ([]byte, error)
	Encrypt(publicKey *rsa.PublicKey, plainText []byte) ([]byte, error)

	EncryptOAEP(publicKey *rsa.PublicKey, plainText []byte) ([]byte, error)
	DecryptOAEP(privateKey *rsa.PrivateKey, cipherText []byte) ([]byte, error)

	Sign(privateKey *rsa.PrivateKey, plainText []byte) ([]byte, []byte, error)
	Verify(publicKey *rsa.PublicKey, hashSum []byte, signature []byte) error
}

type rsaCryptography struct {
}

func (r *rsaCryptography) Verify(publicKey *rsa.PublicKey, hashSum []byte, signature []byte) error {
	return rsa.VerifyPSS(publicKey, crypto.SHA256, hashSum, signature, nil)
}

func (r *rsaCryptography) Sign(privateKey *rsa.PrivateKey, plainText []byte) ([]byte, []byte, error) {
	// We actually sign the hashed message
	msgHash := sha256.New()
	msgHash.Write(plainText)
	msgHashSum := msgHash.Sum(nil)
	// We have to provide a random reader, so every time we sign, we have a different signature
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	return signature, msgHashSum, err
}

// GenerateKeyPair
// How to use:
// Generate a 2048-bits key
// privateKey, publicKey := rsaCrypto.GenerateKeyPair(2048)
func (r *rsaCryptography) GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	// This method requires a random number of bits.
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Println("Generate key pair error: ", err)
	}

	// The public key is part of the PrivateKey struct
	return privateKey, &privateKey.PublicKey
}

func (r *rsaCryptography) Decrypt(privateKey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	h := sha256.New()
	plainText, err := rsa.DecryptOAEP(h, nil, privateKey, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func (r *rsaCryptography) Encrypt(publicKey *rsa.PublicKey, plainText []byte) ([]byte, error) {
	h := sha256.New()
	random := rand.Reader
	cipherText, err := rsa.EncryptOAEP(h, random, publicKey, plainText, nil)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func (r *rsaCryptography) EncryptOAEP(publicKey *rsa.PublicKey, plainText []byte) ([]byte, error) {
	h := sha256.New()
	msgLen := len(plainText)
	step := publicKey.Size() - 2*h.Size() - 2
	var cipherText []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		cipher, err := r.Encrypt(publicKey, plainText[start:finish])
		if err != nil {
			return []byte{}, err
		}
		cipherText = append(cipherText, cipher...)
	}
	return cipherText, nil
}

func (r *rsaCryptography) DecryptOAEP(privateKey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	msgLen := len(cipherText)
	step := privateKey.PublicKey.Size()
	var plainText []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		plain, err := r.Decrypt(privateKey, cipherText[start:finish])
		if err != nil {
			return nil, err
		}
		plainText = append(plainText, plain...)
	}
	return plainText, nil
}

func NewRSACryptography() RSACryptography {
	return &rsaCryptography{}
}
