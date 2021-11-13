package loader

import (
	"os"
)

type fileLoader struct {
}

func (f *fileLoader) Load(filename string) (*os.File, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	return file, err
}

func NewFileLoader() Loader {
	return &fileLoader{}
}
