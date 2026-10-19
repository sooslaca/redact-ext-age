package ageutil

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const (
	// maxIdentityFileSize caps how much of an encrypted identities file is read
	// into memory, so that a mistaken or hostile file cannot exhaust it. An
	// identities file holds a handful of private keys, so a container of this
	// size is not a key.
	maxIdentityFileSize = 1 << 20

	// maxIdentityHeaderPeek is how much of an identities file is inspected to
	// tell age ciphertext from a plain list of private keys. It bounds the
	// amount of leading space that is tolerated before a container header.
	maxIdentityHeaderPeek = 1024

	// scryptStanzaType names the stanza of a container encrypted to a
	// passphrase, as opposed to one encrypted to a public key.
	scryptStanzaType = "scrypt"
)

var (
	// ErrPassphraseUnavailable reports that a passphrase-protected identities
	// file cannot be read, because there is no terminal to ask for it on. An
	// extension that cannot ask reports itself not applicable, so that redact
	// can use one of the other extensions.
	ErrPassphraseUnavailable = errors.New("no terminal is available to ask for the passphrase of an age identities file")

	// ErrIncorrectPassphrase reports that the passphrase entered does not open
	// the identities file. Unlike a file the extension cannot use, this is an
	// unambiguous mistake by the user who was asked, so it is reported as a
	// failure rather than as a missing identity.
	ErrIncorrectPassphrase = errors.New("incorrect passphrase")

	// ErrNoPassphraseEntered reports an empty passphrase, which age does not
	// accept. It is reported apart from ErrIncorrectPassphrase, so that the
	// user is not told to double-check a passphrase they did not type.
	ErrNoPassphraseEntered = errors.New("no passphrase was entered")

	// errNotPassphraseEncrypted reports an identities file that holds age
	// ciphertext encrypted to a public key. The passphrase of such a file is
	// unknown to this extension, so the file contributes no identity.
	errNotPassphraseEncrypted = errors.New("age identities file is encrypted to a public key, not to a passphrase")
)

// PassphraseFunc asks the user for the passphrase of an encrypted age
// identities file. Implementations report ErrPassphraseUnavailable when there
// is nobody to ask, and must not write to stdout: redact reads the Key Exchange
// collection from there.
type PassphraseFunc func(prompt string) (string, error)

// containerKind tells what an identities file holds.
type containerKind int

const (
	// plainIdentities is the age identities file format: a list of private keys
	// in the clear, which age.ParseIdentities reads.
	plainIdentities containerKind = iota

	// binaryContainer is age ciphertext.
	binaryContainer

	// armoredContainer is age ciphertext in its ASCII armored form, which is
	// what age -a and age-keygen -p write.
	armoredContainer
)

// passphraseIdentity opens an age container encrypted to a passphrase, asking
// for it through passphrase once age reaches the scrypt recipient of the
// container.
type passphraseIdentity struct {
	prompt     string
	passphrase PassphraseFunc
}

// newPassphraseIdentity prepares an identity that asks for the passphrase of
// the identities file name when it is needed.
func newPassphraseIdentity(name string, passphrase PassphraseFunc) *passphraseIdentity {
	return &passphraseIdentity{
		prompt:     fmt.Sprintf("Enter passphrase for age identities file %q:", name),
		passphrase: passphrase,
	}
}

// Unwrap implements age.Identity.
func (id *passphraseIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if !hasScryptStanza(stanzas) {
		// Report a mismatch before asking, so that a container encrypted to a
		// public key does not prompt for a passphrase that cannot open it.
		return nil, age.ErrIncorrectIdentity
	}

	value, err := id.passphrase(id.prompt)
	if err != nil {
		return nil, err
	}

	if value == "" {
		return nil, ErrNoPassphraseEntered
	}

	identity, err := age.NewScryptIdentity(value)
	if err != nil {
		return nil, fmt.Errorf("using the age passphrase: %w", err)
	}

	fileKey, err := identity.Unwrap(stanzas)
	if err != nil {
		if errors.Is(err, age.ErrIncorrectIdentity) {
			// Join, so that Decrypt goes on treating this identity as one that
			// does not match, while the caller can still tell a wrong passphrase
			// from a file encrypted to a public key.
			return nil, errors.Join(age.ErrIncorrectIdentity, ErrIncorrectPassphrase)
		}

		return nil, err
	}

	return fileKey, nil
}

func hasScryptStanza(stanzas []*age.Stanza) bool {
	for _, stanza := range stanzas {
		if stanza.Type == scryptStanzaType {
			return true
		}
	}

	return false
}

// readIdentities reads an age identities file: either a plain list of private
// keys, or age ciphertext holding one, which is how a passphrase-protected key
// is stored. The container is opened here, asking passphrase once, because the
// private keys are needed in the clear to match the Key Exchange files of the
// repository.
func readIdentities(name string, reader *bufio.Reader, passphrase PassphraseFunc) ([]age.Identity, error) {
	kind := classifyIdentities(reader)
	if kind == plainIdentities {
		return parseIdentities(reader)
	}

	return parseEncryptedIdentities(name, reader, kind, passphrase)
}

// classifyIdentities tells what an identities file holds, from its header. The
// age library reads a plain list of private keys and decrypts a container, but
// never decides between the two, so the headers it writes are matched here.
// Leading space before the armored header is tolerated, as elsewhere.
func classifyIdentities(reader *bufio.Reader) containerKind {
	peeked, _ := reader.Peek(maxIdentityHeaderPeek) //nolint:errcheck // A short read is the end of a small file.

	switch {
	case bytes.HasPrefix(peeked, []byte("age-encryption")):
		return binaryContainer
	case bytes.HasPrefix(bytes.TrimLeft(peeked, " \t\r\n"), []byte(armor.Header)):
		return armoredContainer
	default:
		return plainIdentities
	}
}

// parseEncryptedIdentities reads an identities file that holds age ciphertext,
// which is what 'age-keygen -p' and 'age -a -p' write.
func parseEncryptedIdentities(name string, reader *bufio.Reader, kind containerKind,
	passphrase PassphraseFunc,
) ([]age.Identity, error) {
	if passphrase == nil {
		return nil, ErrPassphraseUnavailable
	}

	var source io.Reader = reader

	if kind == armoredContainer {
		source = armor.NewReader(reader)
	}

	ciphertext, err := io.ReadAll(io.LimitReader(source, maxIdentityFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading age identities file: %w", err)
	}

	if len(ciphertext) > maxIdentityFileSize {
		return nil, fmt.Errorf("reading age identities file: larger than %d bytes", maxIdentityFileSize)
	}

	plaintext := bytes.Buffer{}
	if err := Decrypt(bytes.NewReader(ciphertext), &plaintext, newPassphraseIdentity(name, passphrase)); err != nil {
		return nil, containerError(err)
	}

	return parseIdentities(&plaintext)
}

// containerError sorts the failure to open an encrypted identities file into
// the outcomes the caller reports. Errors that are not one of the passphrase
// cases are wrapped, so that the user still learns what went wrong.
func containerError(err error) error {
	switch {
	case errors.Is(err, ErrIncorrectPassphrase):
		return ErrIncorrectPassphrase
	case errors.Is(err, ErrNoPassphraseEntered):
		return ErrNoPassphraseEntered
	case errors.Is(err, ErrPassphraseUnavailable):
		return ErrPassphraseUnavailable
	case errors.Is(err, age.ErrIncorrectIdentity):
		return errNotPassphraseEncrypted
	default:
		return fmt.Errorf("reading age identities file: %w", err)
	}
}

// parseIdentities reads a plain list of private keys. age reports "no
// identities found" for a file that holds only comments and blank lines; that
// is an empty set here, not a failure.
func parseIdentities(reader io.Reader) ([]age.Identity, error) {
	identities, err := age.ParseIdentities(reader)
	if err != nil {
		if err.Error() == "no identities found" {
			return nil, nil
		}

		return nil, fmt.Errorf("reading age identities file: %w", err)
	}

	return identities, nil
}
