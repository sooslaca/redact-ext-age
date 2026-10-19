// Package ageutil wraps the filippo.io/age library with the small set of
// helpers the age Key Exchange extension needs: stream encryption and
// decryption, parsing of single recipient and identity strings, reading of
// identities and recipients files, and discovery of local identities.
package ageutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// Encrypt reads plaintext from reader and writes age ciphertext for the given
// recipients to writer.
func Encrypt(reader io.Reader, writer io.Writer, recipients ...age.Recipient) error {
	encrypter, err := age.Encrypt(writer, recipients...)
	if err != nil {
		return fmt.Errorf("starting age encryption: %w", err)
	}

	if _, err := io.Copy(encrypter, reader); err != nil {
		_ = encrypter.Close()

		return fmt.Errorf("writing age plaintext: %w", err)
	}

	if err := encrypter.Close(); err != nil {
		return fmt.Errorf("closing age encryption: %w", err)
	}

	return nil
}

// Decrypt reads age ciphertext from reader and writes the recovered plaintext to
// writer using the supplied identities. It returns an error wrapping
// age.ErrIncorrectIdentity when none of the identities can open the ciphertext.
func Decrypt(reader io.Reader, writer io.Writer, identities ...age.Identity) error {
	decrypter, err := age.Decrypt(reader, identities...)
	if err != nil {
		return fmt.Errorf("decrypting age ciphertext: %w", err)
	}

	if _, err := io.Copy(writer, decrypter); err != nil {
		return fmt.Errorf("reading age plaintext: %w", err)
	}

	return nil
}

// ParseRecipient parses a single age recipient (public key) string. The age
// library only exposes file-based parsing, so the type dispatch is replicated
// here for the single-string case.
func ParseRecipient(text string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(text, "age1pq1"):
		return age.ParseHybridRecipient(text)
	case strings.HasPrefix(text, "age1"):
		return age.ParseX25519Recipient(text)
	default:
		// The value may be a private key handed to a recipient argument, so do
		// not echo it back.
		return nil, errors.New("unknown age recipient type")
	}
}

// ParseIdentity parses a single age identity (private key) string. The error
// never repeats the argument, which may hold private key material.
func ParseIdentity(text string) (age.Identity, error) {
	switch {
	case strings.HasPrefix(text, "AGE-SECRET-KEY-1"):
		return age.ParseX25519Identity(text)
	case strings.HasPrefix(text, "AGE-SECRET-KEY-PQ-1"):
		return age.ParseHybridIdentity(text)
	default:
		return nil, errors.New("unknown age identity type")
	}
}

// ParseIdentitiesFile reads an age identities file. A missing file yields no
// identities and no error, so discovery against an unconfigured host is not a
// failure. A file holding only comments and blank lines likewise yields no
// identities.
func ParseIdentitiesFile(filename string) ([]age.Identity, error) {
	file, err := os.Open(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, fmt.Errorf("opening age identities file: %w", err)
	}
	defer file.Close()

	identities, err := age.ParseIdentities(file)
	if err != nil {
		// age reports this when the file holds no usable identity; treat it as
		// an empty set rather than an error.
		if err.Error() == "no identities found" {
			return nil, nil
		}

		return nil, fmt.Errorf("reading age identities file: %w", err)
	}

	return identities, nil
}

// ParseRecipientsFile reads an age recipients file. A file holding no usable
// recipient yields no recipients and no error.
func ParseRecipientsFile(filename string) ([]age.Recipient, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("opening age recipients file: %w", err)
	}
	defer file.Close()

	recipients, err := age.ParseRecipients(file)
	if err != nil {
		if err.Error() == "no recipients found" {
			return nil, nil
		}

		return nil, fmt.Errorf("reading age recipients file: %w", err)
	}

	return recipients, nil
}

// RecipientText returns the canonical bech32 encoding of an age recipient
// (public key). The age library exposes String only on the concrete
// implementations, not on the Recipient interface, so the type dispatch is
// replicated here.
func RecipientText(recipient age.Recipient) (string, error) {
	switch rec := recipient.(type) {
	case *age.X25519Recipient:
		return rec.String(), nil
	case *age.HybridRecipient:
		return rec.String(), nil
	default:
		return "", fmt.Errorf("unsupported age recipient type %T", recipient)
	}
}

// RecipientString returns the bech32 recipient (public key) that matches an
// identity.
func RecipientString(identity age.Identity) (string, error) {
	switch id := identity.(type) {
	case *age.X25519Identity:
		return id.Recipient().String(), nil
	case *age.HybridIdentity:
		return id.Recipient().String(), nil
	default:
		return "", fmt.Errorf("unsupported age identity type %T", identity)
	}
}

// PrintRecipientTo writes a human-readable one-line description of an age
// recipient.
func PrintRecipientTo(writer io.Writer, recipient string) error {
	if _, err := fmt.Fprintf(writer, "age recipient: %s\n", recipient); err != nil {
		return fmt.Errorf("printing age recipient: %w", err)
	}

	return nil
}

// DefaultIdentityFile returns the path of the age identities file to read when
// no keyfile= setting is supplied: the AGE_IDENTITIES_FILE environment
// variable, or the per-user default. It returns an empty string when neither
// can be determined.
func DefaultIdentityFile() string {
	if env := os.Getenv("AGE_IDENTITIES_FILE"); env != "" {
		return env
	}

	config, err := os.UserConfigDir()
	if err != nil {
		return ""
	}

	return filepath.Join(config, "age", "identities")
}
