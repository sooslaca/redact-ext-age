//go:build windows

package main

import (
	"os"
)

// openTerminal opens the console of the process, which can be asked for a
// passphrase even when the standard streams belong to whoever started the
// extension. Windows has no /dev/tty: CONIN$ and CONOUT$ name the input and
// output buffers of the console instead.
func openTerminal() (*os.File, *os.File, error) {
	input, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}

	output, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		input.Close() // nolint:errcheck

		return nil, nil, err
	}

	return input, output, nil
}
