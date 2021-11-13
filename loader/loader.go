package loader

import (
	"os"
)

type Loader interface {
	Load(filename string) (*os.File, error)
}
