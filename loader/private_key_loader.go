package loader

import (
	"bufio"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"github.com/youmark/pkcs8"
	"os"
)

type PrivateKeyLoader interface {
	Load(filename string, passPhrase string) (*rsa.PrivateKey, error)
}

type privateKeyLoader struct {
	FileLoader Loader
}

func (p *privateKeyLoader) Load(filename string, passPhrase string) (*rsa.PrivateKey, error) {
	// Open file
	file, err := p.FileLoader.Load(filename)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) { _ = file.Close() }(file)

	// Create a byte from file info
	pemFileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	var size = pemFileInfo.Size()
	pemBytes := make([]byte, size)

	// Create new reader read file to buffer
	buf := bufio.NewReader(file)
	_, err = buf.Read(pemBytes)
	if err != nil {
		return nil, err
	}

	// Now decode the pem byte
	data, _ := pem.Decode(pemBytes)
	if data == nil {
		return nil, errors.New("could not decode pem file")
	}

	// Parse encrypted private keys with pass phrase
	decryptPrivateKey, err := pkcs8.ParsePKCS8PrivateKey(data.Bytes, []byte(passPhrase))
	if err != nil {
		return nil, errors.New("could not parse private keys pem with pass phase")
	}

	return decryptPrivateKey.(*rsa.PrivateKey), nil
}

func NewPrivateKeyLoader(fileLoader Loader) PrivateKeyLoader {
	return &privateKeyLoader{
		FileLoader: fileLoader,
	}
}
