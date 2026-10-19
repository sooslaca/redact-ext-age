package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"

	"github.com/urfave/cli/v3"

	"redact-ext-age/ageutil"
)

func cmdGet() *cli.Command {
	return command("get", "Export a Key Exchange collection using a local age identity", getAction)
}

type localIdentity struct {
	identity age.Identity
	text     string
}

func getAction(_ context.Context, cmd *cli.Command) error {
	settings, err := parseSettings(cmd.Args().Slice(), "agekey", "keyfile")
	if err != nil {
		return err
	}

	selector := settings.identity()

	available, err := availableKeys(settings, selector, promptPassphrase)
	if err != nil {
		return err
	}

	if len(available) == 0 {
		if selector != "" {
			return notApplicable(fmt.Errorf("%w: %q", ErrIdentityHasNoKeyExchangeCopy, selector))
		}

		return notApplicable(ErrNoLocalKeyExchangeCopy)
	}

	if len(available) > 1 {
		fmt.Fprintln(os.Stderr, "Multiple local age identities have a Key Exchange copy. Retry with agekey=<recipient>.")
		printCandidates(available)

		return missing(ErrAgeIdentitySelectionRequired)
	}

	collection, err := loadExchangeKey(available[0])
	if err != nil {
		return err
	}

	if _, err := os.Stdout.Write(collection); err != nil {
		return failed(fmt.Errorf("exporting Key Exchange collection: %w", err))
	}

	return nil
}

// loadIdentities collects the age identities available locally, from the
// keyfile= setting or the default age identities file, asking prompt for the
// passphrase of an identities file that holds its keys as age ciphertext.
//
// The age extension is one of the extensions redact may use, so an identities
// file this extension cannot read is reported and skipped: redact keeps the
// identities it could read, and is free to try the next extension. A passphrase
// that was asked for and refused is the exception, because the user was spoken
// to and no other extension can answer better.
func loadIdentities(settings settings, prompt ageutil.PassphraseFunc) ([]localIdentity, error) {
	filenames := settings.values("keyfile")
	if len(filenames) == 0 {
		if def := ageutil.DefaultIdentityFile(); def != "" {
			filenames = []string{def}
		}
	}

	identities := make([]localIdentity, 0)
	locked := ""

	for _, filename := range filenames {
		parsed, err := ageutil.ParseIdentitiesFile(filename, prompt)

		switch {
		case err == nil:
		case errors.Is(err, ageutil.ErrIncorrectPassphrase), errors.Is(err, ageutil.ErrNoPassphraseEntered):
			return nil, failed(fmt.Errorf("using age identities file %s: %w", filename, err))
		case errors.Is(err, ageutil.ErrPassphraseUnavailable):
			fmt.Fprintf(os.Stderr, "Ignoring age identities file %s: no terminal to type its passphrase. "+
				"Run redact from a terminal, or use an identities file without a passphrase.\n", filename)
			locked = filename

			continue
		default:
			fmt.Fprintf(os.Stderr, "Ignoring age identities file %s: %v\n", filename, err)

			continue
		}

		identities = append(identities, identitiesOf(parsed)...)
	}

	if locked != "" && len(identities) == 0 {
		return nil, notApplicable(fmt.Errorf("age identities file %s: %w", locked, ageutil.ErrPassphraseUnavailable))
	}

	return identities, nil
}

// identitiesOf keeps the identities whose recipient can be derived. One whose
// recipient cannot be derived is skipped, like an unavailable GPG key.
func identitiesOf(parsed []age.Identity) []localIdentity {
	identities := make([]localIdentity, 0, len(parsed))

	for _, identity := range parsed {
		text, err := ageutil.RecipientString(identity)
		if err != nil {
			continue
		}

		identities = append(identities, localIdentity{identity: identity, text: text})
	}

	return identities
}

func availableKeys(settings settings, selector string, prompt ageutil.PassphraseFunc) ([]localIdentity, error) {
	identities, err := loadIdentities(settings, prompt)
	if err != nil {
		return nil, err
	}

	if selector != "" {
		matched := make([]localIdentity, 0, len(identities))
		for _, item := range identities {
			if matchesRecipient(item.text, selector) {
				matched = append(matched, item)
			}
		}

		if len(matched) == 0 {
			return nil, notApplicable(fmt.Errorf("no local age identity matches %q", selector))
		}

		identities = matched
	}

	available := make([]localIdentity, 0, len(identities))

	for _, item := range identities {
		filename := filepath.Join(KeyExchangeDir, ExchangeAgeSecretKeyFile(item.text))

		info, err := os.Stat(filename)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}

			return nil, failed(fmt.Errorf("checking encrypted Key Exchange file %s: %w", filename, err))
		}

		if !info.Mode().IsRegular() {
			continue
		}

		available = append(available, item)
	}

	return available, nil
}

func printCandidates(candidates []localIdentity) {
	for _, item := range candidates {
		if err := ageutil.PrintRecipientTo(os.Stderr, item.text); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to print candidate %s: %v\n", item.text, err)
		}
	}
}

// loadExchangeKey decrypts the Key Exchange copy of a local identity. The
// collection is opaque here: redact reads it back on the other end of the pipe.
func loadExchangeKey(item localIdentity) ([]byte, error) {
	filename := filepath.Join(KeyExchangeDir, ExchangeAgeSecretKeyFile(item.text))

	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		return nil, failed(fmt.Errorf("opening encrypted Key Exchange file: %w", err))
	}

	plaintext := bytes.Buffer{}
	if err := ageutil.Decrypt(bytes.NewReader(ciphertext), &plaintext, item.identity); err != nil {
		return nil, failed(fmt.Errorf("decrypting Key Exchange collection: %w", err))
	}

	return plaintext.Bytes(), nil
}
