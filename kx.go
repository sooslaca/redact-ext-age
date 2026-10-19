package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"redact-ext-age/ageutil"
)

const (
	// KeyExchangeDir is the folder redact keeps Key Exchange material in. It is
	// relative to the repository toplevel, where redact always runs extensions,
	// and must stay in sync with redact's own DefaultKeyExchangeDir.
	KeyExchangeDir = ".redact"

	// ExtAgePubKey is the extension of the age recipient registrations kept in
	// the Key Exchange folder.
	ExtAgePubKey = ".agepub"
	// ExtAgeSecret is the extension of the Key Exchange collection age-encrypted
	// for one recipient.
	ExtAgeSecret = ".agekey"

	// GitAttributesFile is the per-directory git attributes file of the Key
	// Exchange folder.
	GitAttributesFile = ".gitattributes"

	// GitAttributesEntry keeps age ciphertext opaque to git, so that an encrypted
	// Key Exchange collection round-trips byte for byte. redact does not know
	// about the age files, so this extension maintains the entry itself.
	GitAttributesEntry = "*" + ExtAgeSecret + " binary"
)

// ExchangeAgePubKeyFile returns the Key Exchange filename holding the
// registration of an age recipient public key.
func ExchangeAgePubKeyFile(stub string) string {
	return stub + ExtAgePubKey
}

// ExchangeAgeSecretKeyFile returns the Key Exchange filename holding the Key
// Exchange collection age-encrypted for one recipient.
func ExchangeAgeSecretKeyFile(stub string) string {
	return stub + ExtAgeSecret
}

// exchangePath returns the Key Exchange path of a filename stub, preparing the
// folder as redact would: the extension writes into the folder redact reads, so
// it establishes the conventions redact cannot establish for it.
func exchangePath(stub string) (string, error) {
	if err := ensureExchangeDir(); err != nil {
		return "", err
	}

	return filepath.Join(KeyExchangeDir, stub), nil
}

func ensureExchangeDir() error {
	st, err := os.Stat(KeyExchangeDir)
	if err != nil {
		if err := os.MkdirAll(KeyExchangeDir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", KeyExchangeDir, err)
		}

		st, err = os.Stat(KeyExchangeDir)
		if err != nil {
			return fmt.Errorf("checking %s: %w", KeyExchangeDir, err)
		}
	}

	if !st.IsDir() {
		return fmt.Errorf("%q: %w", KeyExchangeDir, ErrExchangeIsNotDir)
	}

	return ensureGitAttributes()
}

// ensureGitAttributes appends the age ciphertext entry to the Key Exchange
// folder's git attributes file, keeping everything already there. redact may
// rewrite this file with its own contents, in which case the entry is restored
// by the next grant.
func ensureGitAttributes() error {
	filename := filepath.Join(KeyExchangeDir, GitAttributesFile)

	data, err := readExchangeFile(filename)
	if err != nil {
		return err
	}

	if strings.Contains(string(data), GitAttributesEntry) {
		return nil
	}

	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		data = append(data, '\n')
	}

	contents := append(data, GitAttributesEntry+"\n"...) //nolint:gocritic

	return writeExchangeFile(filename, contents)
}

// readExchangeFile returns the contents of a Key Exchange file, and nothing if
// it does not exist yet: the extension creates what redact has not created.
func readExchangeFile(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}

		return nil, fmt.Errorf("reading %s: %w", filename, err)
	}

	return data, nil
}

// saveAgeKeyToKX writes the Key Exchange collection to the Key Exchange folder,
// age-encrypted for one recipient.
func saveAgeKeyToKX(recipient age.Recipient, collection []byte) error {
	text, err := ageutil.RecipientText(recipient)
	if err != nil {
		return fmt.Errorf("identifying recipient: %w", err)
	}

	kxstub, err := exchangePath(text)
	if err != nil {
		return err
	}

	cyphertext := bytes.Buffer{}
	if err := ageutil.Encrypt(bytes.NewReader(collection), &cyphertext, recipient); err != nil {
		return fmt.Errorf("encrypting Key Exchange collection: %w", err)
	}

	return writeExchangeFile(ExchangeAgeSecretKeyFile(kxstub), cyphertext.Bytes())
}

// saveAgePubkeyToKX registers an age recipient in the Key Exchange folder, so
// that other users can encrypt the Key Exchange collection for it.
func saveAgePubkeyToKX(recipient age.Recipient) error {
	text, err := ageutil.RecipientText(recipient)
	if err != nil {
		return fmt.Errorf("identifying recipient: %w", err)
	}

	kxstub, err := exchangePath(text)
	if err != nil {
		return err
	}

	return writeExchangeFile(ExchangeAgePubKeyFile(kxstub), []byte(text+"\n"))
}

// writeExchangeFile writes a Key Exchange file through a temporary file in the
// Key Exchange folder, so that a failing write never leaves a truncated file
// behind for git to commit.
func writeExchangeFile(filename string, contents []byte) error {
	tmpfile, err := os.CreateTemp(KeyExchangeDir, "kx-")
	if err != nil {
		return fmt.Errorf("creating temporary file for %s: %w", filename, err)
	}

	defer os.Remove(tmpfile.Name()) // nolint:errcheck

	if _, err := tmpfile.Write(contents); err != nil {
		_ = tmpfile.Close()

		return fmt.Errorf("writing %s: %w", filename, err)
	}

	if err := tmpfile.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", filename, err)
	}

	if err := os.Rename(tmpfile.Name(), filename); err != nil {
		return fmt.Errorf("updating %s: %w", filename, err)
	}

	return nil
}
