package cryptox_test

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/prongbang/go-payload-cryptography/cryptox"
	"github.com/prongbang/go-payload-cryptography/loader"
	"github.com/prongbang/go-payload-cryptography/util"
	"testing"
)

var rsaCrypto cryptox.RSACryptography
var keyLoader loader.PrivateKeyLoader
var privateKey *rsa.PrivateKey

const (
	filename   = "private-key.pem"
	passPhrase = "secret"
)

func init() {
	fileLoader := loader.NewFileLoader()
	keyLoader = loader.NewPrivateKeyLoader(fileLoader)
	rsaCrypto = cryptox.NewRSACryptography()

	filePath := util.GetRootPath("go-payload-cryptography")
	privateKey, _ = keyLoader.Load(fmt.Sprintf("%s/%s", filePath, filename), passPhrase)
}

func TestCustomEncryptOAEP(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{
		"username": "userX",
		"password": "passX",
	})
	cipherText, err := rsaCrypto.EncryptOAEP(&privateKey.PublicKey, payload)

	if err != nil && len(cipherText) == 0 {
		t.Error("Encrypt failure")
	}
}

func TestCustomDecryptOAEP(t *testing.T) {
	encrypted := "JmZf7yFglhJ9FUcy3mDrNoLIzcofjWYucrnf0A+45V0sr5Hfd197J4wUAATcosMAi3xbce00rxiI++HQ8Z3Y0YIH7ZeE3RgQ/DXwUSTbafqkdsB9BFkHgn5hZ/MgqmuGt1b/L5vWx50cUSDG1pmQAOmdZ5TNK0kdwOzC5xrO0CWiSgHXud9zSqRXn3tcYrzLehDks3Hst2Ep01wN9fM6d20z8Kqa2wP/sjBonV9ceTwtccPP+PRFuUg20et7zoICpI3/H3IsgQvIuLvRPfNSvrzewJqFP62VmCjEjy5dkz8B7iqkZJR872+2m/Bm8w3gRmGTDIqGfmHUH0+QHBzqKg=="
	cipherText, _ := base64.StdEncoding.DecodeString(encrypted)
	plainText, _ := rsaCrypto.DecryptOAEP(privateKey, cipherText)

	// Parse to map
	payload := map[string]string{}
	_ = json.Unmarshal(plainText, &payload)

	if payload["username"] != "userX" || payload["password"] != "passX" {
		t.Error("Decrypt failure")
	}
}

func TestEncrypt(t *testing.T) {
	payload := "Lorem Ipsum is simply dummy text of the printing and typesetting industry."
	cipherByte, _ := rsaCrypto.Encrypt(&privateKey.PublicKey, []byte(payload))
	cipherText := base64.StdEncoding.EncodeToString(cipherByte)
	if cipherText == "" {
		t.Error("Encrypt failure")
	}
}

func BenchmarkCustomDecryptOAEP(b *testing.B) {
	encrypted := "JmZf7yFglhJ9FUcy3mDrNoLIzcofjWYucrnf0A+45V0sr5Hfd197J4wUAATcosMAi3xbce00rxiI++HQ8Z3Y0YIH7ZeE3RgQ/DXwUSTbafqkdsB9BFkHgn5hZ/MgqmuGt1b/L5vWx50cUSDG1pmQAOmdZ5TNK0kdwOzC5xrO0CWiSgHXud9zSqRXn3tcYrzLehDks3Hst2Ep01wN9fM6d20z8Kqa2wP/sjBonV9ceTwtccPP+PRFuUg20et7zoICpI3/H3IsgQvIuLvRPfNSvrzewJqFP62VmCjEjy5dkz8B7iqkZJR872+2m/Bm8w3gRmGTDIqGfmHUH0+QHBzqKg=="
	cipherText, _ := base64.StdEncoding.DecodeString(encrypted)
	for i := 0; i < b.N; i++ {
		_, err := rsaCrypto.DecryptOAEP(privateKey, cipherText)
		if err != nil {
			return
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	encrypted := "U4wywFZXBPF876eGXXNe92Ux/JMJUJ3H96Hwe0AShKBUlrkQSQOey9JS822Y6AqxvZqP65/38ycZQlmx2oy02HaxhHob0QE3n8P0HOkV28qB6juIhbmrV4576pLfSpZE0YYTE01oFciOpUa+ee+9fu8EVwazzfl9hdY6Bb5R51gHMlGAM4mL8gLkR5SmSQZULsgOtNF0cFEMS4Zd/ktybpZgN9ycRifWUT8+3UgyBVroJfpFmU6Ruxo0AvXqXMR+3xbPI5hOonoc89O1dmfRsjlg8W+/jCVXZIpwEGQ1C8TpXq7PNmXyWwgvUO7yZ2x/AalNllsKtizhcJ+Nf6Qkeg=="
	cipherText, _ := base64.StdEncoding.DecodeString(encrypted)
	for i := 0; i < b.N; i++ {
		_, err := rsaCrypto.Decrypt(privateKey, cipherText)
		if err != nil {
			return
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	payload := "Lorem Ipsum is simply dummy text of the printing and typesetting industry."
	for i := 0; i < b.N; i++ {
		_, err := rsaCrypto.Encrypt(&privateKey.PublicKey, []byte(payload))
		if err != nil {
			return
		}
	}
}

func TestSignAndVerify(t *testing.T) {
	message := []byte("Message + Signature")
	signature, hasSum, _ := rsaCrypto.Sign(privateKey, message)

	err := rsaCrypto.Verify(&privateKey.PublicKey, hasSum, signature)
	if err != nil {
		t.Error("Sign message and Verify failure.")
	}
}
