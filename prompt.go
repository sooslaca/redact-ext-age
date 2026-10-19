package main

import (
	"fmt"
	"os"

	"golang.org/x/term"

	"redact-ext-age/ageutil"
)

// promptPassphrase asks the user for the passphrase of an encrypted age
// identities file. It is a variable so that the tests can answer without a
// terminal.
var promptPassphrase ageutil.PassphraseFunc = terminalPassphrase

// terminalPassphrase asks for a passphrase on the terminal. The standard
// streams are not used for that: redact passes the Key Exchange collection on
// stdin and reads it back on stdout, so a prompt written to stdout would be
// taken for collection data, and a passphrase read from stdin would be the
// collection.
func terminalPassphrase(prompt string) (string, error) {
	input, output, err := withTerminal()
	if err != nil {
		return "", err
	}
	defer closeTerminal(input, output)

	if _, err := fmt.Fprint(output, prompt+" "); err != nil {
		return "", fmt.Errorf("writing the passphrase prompt: %w", err)
	}

	value, err := term.ReadPassword(int(input.Fd()))
	if err != nil {
		return "", fmt.Errorf("reading the passphrase: %w", err)
	}

	// ReadPassword switches echo off, so the Enter key that ends the passphrase
	// leaves no line behind: print one, or the next message starts on the same
	// line as the prompt.
	if _, err := fmt.Fprintln(output); err != nil {
		return "", fmt.Errorf("ending the passphrase prompt: %w", err)
	}

	return string(value), nil
}

// withTerminal returns the streams to prompt the user on: the controlling
// terminal, so that an extension redact starts can still ask, or the standard
// streams when they are a terminal and there is no controlling terminal to
// open. It reports ErrPassphraseUnavailable when there is nobody to ask.
func withTerminal() (*os.File, *os.File, error) {
	input, output, err := openTerminal()
	if err == nil {
		return input, output, nil
	}

	if term.IsTerminal(int(os.Stdin.Fd())) {
		return os.Stdin, os.Stderr, nil
	}

	return nil, nil, ageutil.ErrPassphraseUnavailable
}

// closeTerminal closes what openTerminal opened, once when the prompt and the
// passphrase share a stream.
func closeTerminal(input, output *os.File) {
	if output != nil {
		output.Close() // nolint:errcheck
	}

	if input != nil && input != output {
		input.Close() // nolint:errcheck
	}
}
