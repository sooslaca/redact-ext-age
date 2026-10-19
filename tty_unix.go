//go:build !windows

package main

import (
	"os"
)

// openTerminal opens the controlling terminal of the process, which can be
// asked for a passphrase even when the standard streams belong to whoever
// started the extension. The same stream serves the prompt and the passphrase.
func openTerminal() (*os.File, *os.File, error) {
	file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}

	return file, file, nil
}
