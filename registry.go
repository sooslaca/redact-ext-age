package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"

	"redact-ext-age/ageutil"
)

// recipient is one age registration found in the Key Exchange directory: the
// parsed recipient, its canonical bech32 text, and the file it came from.
type recipient struct {
	key      age.Recipient
	text     string
	filename string
	stub     string
}

// readRecipients enumerates age recipient registrations in the Key Exchange
// directory. A missing directory holds no registrations and is not an error.
// Per-file problems are collected so one damaged registration does not hide
// the healthy ones.
func readRecipients() ([]recipient, []error) {
	entries, err := os.ReadDir(KeyExchangeDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}

		return nil, []error{fmt.Errorf("reading Key Exchange directory: %w", err)}
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	recipients := make([]recipient, 0, len(entries))

	var failures []error

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ExtAgePubKey) {
			continue
		}

		filename := filepath.Join(KeyExchangeDir, entry.Name())

		data, err := os.ReadFile(filename)
		if err != nil {
			failures = append(failures, fmt.Errorf("opening recipient registration %s: %w", filename, err))

			continue
		}

		parsed, err := age.ParseRecipients(bytes.NewReader(data))
		if err != nil {
			failures = append(failures, fmt.Errorf("loading recipient registration %s: %w", filename, err))

			continue
		}

		if len(parsed) != 1 {
			failures = append(failures, fmt.Errorf("recipient registration %s contains %d recipients", filename, len(parsed)))

			continue
		}

		text, err := ageutil.RecipientText(parsed[0])
		if err != nil {
			failures = append(failures, fmt.Errorf("identifying recipient registration %s: %w", filename, err))

			continue
		}

		stub := strings.TrimSuffix(filename, ExtAgePubKey)
		recipients = append(recipients, recipient{
			key:      parsed[0],
			text:     text,
			filename: filename,
			stub:     stub,
		})
	}

	return recipients, failures
}

func (recipient recipient) matches(selector string) bool {
	return matchesRecipient(recipient.text, selector)
}

// matchesRecipient reports whether selector identifies the recipient encoded
// by text. age recipients have no user-ID names, so matching is on the bech32
// string: prefix or suffix for short bech32 fragments (like a GPG key-id
// match), substring otherwise.
func matchesRecipient(text, selector string) bool {
	selector = strings.ToLower(strings.TrimSpace(selector))
	if selector == "" {
		return false
	}

	if isBech32Fragment(selector) && (strings.HasPrefix(text, selector) || strings.HasSuffix(text, selector)) {
		return true
	}

	return strings.Contains(text, selector)
}

// isBech32Fragment reports whether value is a plausible fragment of a bech32
// recipient string: lowercase alphanumeric, including the "1" separator.
func isBech32Fragment(value string) bool {
	if value == "" {
		return false
	}

	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'z') {
			return false
		}
	}

	return true
}

func matchingRecipients(recipients []recipient, selectors []string) []recipient {
	matched := make([]recipient, 0, len(recipients))
	for _, item := range recipients {
		for _, selector := range selectors {
			if item.matches(selector) {
				matched = append(matched, item)

				break
			}
		}
	}

	return matched
}
