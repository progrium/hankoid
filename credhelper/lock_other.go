//go:build !unix

package credhelper

import (
	"errors"
	"os"
	"time"
)

// lockFile uses an exclusive-create lock file where flock isn't available.
func lockFile(path string) (func(), error) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}
