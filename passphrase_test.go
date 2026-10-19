package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"redact-ext-age/ageutil"
)

// An 'age -p' user keeps the private keys of an identities file inside an age
// container, so unlocking a repository with such a file starts with a passphrase
// prompt: one prompt, naming the file, and the collection exported byte for byte.
func TestGetWithPassphraseProtectedIdentitiesFile(t *testing.T) {
	const passphrase = "the passphrase of this identities file"

	// Swapped before the extension runs: the real prompt reads the controlling
	// terminal of whoever runs the test. The count below covers the grant too,
	// which must not need the passphrase of an identities file at all.
	prompts := answerPassphrase(t, passphrase, nil)
	filename := passphraseRepo(t, passphrase)

	stdout, stderr, err := runExtension(t, []string{"redact-ext-age", "get"}, nil)
	if err != nil {
		t.Fatalf("get with a passphrase protected identities file: %v (%s)", err, stderr)
	}

	if stdout != string(testCollection) {
		t.Errorf("get exported %q, want the original collection", stdout)
	}

	if len(*prompts) != 1 {
		t.Fatalf("the extension asked %d passphrases, want 1: %q", len(*prompts), *prompts)
	}

	if !strings.Contains((*prompts)[0], filename) {
		t.Errorf("the prompt does not name %s: %s", filename, (*prompts)[0])
	}
}

// A passphrase that was asked for and got wrong is reported as a failure, without
// printing a collection: the user was spoken to, and no other extension could
// answer that prompt better, so redact stops the chain here.
func TestGetRefusesWrongPassphrase(t *testing.T) {
	const passphrase = "the passphrase of this identities file"

	typed := "not the passphrase of this file"

	prompts := answerPassphrase(t, typed, nil)
	passphraseRepo(t, passphrase)

	stdout, stderr, err := runExtension(t, []string{"redact-ext-age", "get"}, nil)
	if code := ExitCode(err); code != Failure {
		t.Errorf("get with a wrong passphrase: exit code %d, want %d", code, Failure)
	}

	if stdout != "" {
		t.Errorf("get with a wrong passphrase printed a collection: %s", stdout)
	}

	if len(*prompts) != 1 {
		t.Errorf("the extension asked %d passphrases, want 1: %q", len(*prompts), *prompts)
	}

	// redact reads the collection on stdout, and a passphrase is a secret: what
	// the user typed belongs in neither stream, nor in a message they may have
	// to paste somewhere.
	if strings.Contains(stdout+stderr, typed) {
		t.Errorf("the extension repeated the passphrase the user typed: %s", stderr)
	}
}

// An identities file whose passphrase nobody can type cannot be read, and that is
// not a failure: another key, or another extension, may still unlock the
// collection, so redact is told that this extension does not apply.
func TestGetWithoutTerminalForPassphrase(t *testing.T) {
	const passphrase = "the passphrase of this identities file"

	prompts := answerPassphrase(t, "", ageutil.ErrPassphraseUnavailable)
	filename := passphraseRepo(t, passphrase)

	stdout, stderr, err := runExtension(t, []string{"redact-ext-age", "get"}, nil)
	if code := ExitCode(err); code != NotApplicable {
		t.Errorf("get without a terminal: exit code %d, want %d", code, NotApplicable)
	}

	if stdout != "" {
		t.Errorf("get without a terminal printed a collection: %s", stdout)
	}

	if !strings.Contains(stderr, "no terminal to type its passphrase") {
		t.Errorf("get without a terminal did not say how to get one: %s", stderr)
	}

	if !strings.Contains(stderr, filename) {
		t.Errorf("get without a terminal did not name %s: %s", filename, stderr)
	}

	if len(*prompts) != 1 {
		t.Errorf("the extension asked %d passphrases, want 1: %q", len(*prompts), *prompts)
	}
}

// The age extension is one of the extensions redact may use, so an identities
// file it cannot read is reported and skipped rather than ending the run: a key
// it can read still unlocks the collection.
func TestGetIgnoresUnusableIdentitiesFile(t *testing.T) {
	const passphrase = "the passphrase of this identities file"

	unusable := []struct {
		name        string
		contents    func(t *testing.T) []byte
		promptErr   error
		wantPrompts int
		wantStderr  string
	}{
		{
			name:       "not an age identities file",
			contents:   func(*testing.T) []byte { return []byte("not an age private key\n") },
			wantStderr: "Ignoring age identities file",
		},
		{
			name: "a passphrase nobody is there to type",
			contents: func(t *testing.T) []byte {
				keyText, _ := newIdentity(t)

				return passphraseContainer(t, keyText, passphrase)
			},
			promptErr:   ageutil.ErrPassphraseUnavailable,
			wantPrompts: 1,
			wantStderr:  "no terminal to type its passphrase",
		},
	}

	for _, one := range unusable {
		t.Run(one.name, func(t *testing.T) {
			initRepo(t)

			usableKey, usableRecipient := newIdentity(t)
			usableFile := identitiesFile(t, []byte(usableKey))
			unusableFile := identitiesFile(t, one.contents(t))

			prompts := answerPassphrase(t, "", one.promptErr)

			grantCollection(t, testCollection, usableRecipient)

			stdout, stderr, err := runExtension(t, []string{
				"redact-ext-age", "get",
				"keyfile=" + unusableFile, "keyfile=" + usableFile,
			}, nil)
			if err != nil {
				t.Fatalf("get with %s among the identities files: %v (%s)", one.name, err, stderr)
			}

			if stdout != string(testCollection) {
				t.Errorf("get exported %q, want the original collection", stdout)
			}

			if !strings.Contains(stderr, one.wantStderr) {
				t.Errorf("get did not report the unusable identities file (%s): %s", one.wantStderr, stderr)
			}

			if !strings.Contains(stderr, unusableFile) {
				t.Errorf("get did not name %s: %s", unusableFile, stderr)
			}

			if len(*prompts) != one.wantPrompts {
				t.Errorf("the extension asked %d passphrases, want %d: %q",
					len(*prompts), one.wantPrompts, *prompts)
			}
		})
	}
}

// answerPassphrase answers a passphrase prompt the way a user would type it, and
// returns what the extension asked while the test ran. The real prompt reads the
// controlling terminal, which a test must not block on.
func answerPassphrase(t *testing.T, answer string, promptErr error) *[]string {
	t.Helper()

	prompts := &[]string{}
	previous := promptPassphrase

	promptPassphrase = func(prompt string) (string, error) {
		*prompts = append(*prompts, prompt)

		return answer, promptErr
	}

	t.Cleanup(func() { promptPassphrase = previous })

	return prompts
}

// passphraseRepo puts a repository under test in place, holding the Key Exchange
// collection granted to one identity whose private key sits in a passphrase
// protected identities file, as 'age -p' writes one. It points the environment
// of a user who keeps their keys there at that file, and returns its name.
func passphraseRepo(t *testing.T, passphrase string) string {
	t.Helper()

	initRepo(t)

	keyText, recipient := newIdentity(t)
	filename := identitiesFile(t, passphraseContainer(t, keyText, passphrase))

	t.Setenv("AGE_IDENTITIES_FILE", filename)

	grantCollection(t, testCollection, recipient)

	return filename
}

// grantCollection grants the Key Exchange collection to the recipients, as redact
// does before it later asks this extension to export the collection again.
func grantCollection(t *testing.T, collection []byte, recipients ...string) {
	t.Helper()

	args := make([]string, 0, len(recipients)+2)
	args = append(args, "redact-ext-age", "grant")

	for _, recipient := range recipients {
		args = append(args, "recipient="+recipient)
	}

	if _, stderr, err := runExtension(t, args, collection); err != nil {
		t.Fatalf("grant: %v (%s)", err, stderr)
	}
}

// newIdentity returns a fresh age identity with the line 'age-keygen' writes for
// it into an identities file, and the recipient that file grants access to.
func newIdentity(t *testing.T) (keyText, recipient string) {
	t.Helper()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generating an age identity: %v", err)
	}

	text, err := ageutil.RecipientString(identity)
	if err != nil {
		t.Fatalf("deriving the recipient of an age identity: %v", err)
	}

	return identity.String() + "\n", text
}

// identitiesFile stores contents as an identities file of its own.
func identitiesFile(t *testing.T, contents []byte) string {
	t.Helper()

	filename := filepath.Join(t.TempDir(), "identities")
	if err := os.WriteFile(filename, contents, 0o600); err != nil {
		t.Fatalf("writing identities file: %v", err)
	}

	return filename
}

// passphraseContainer holds the private keys of an identities file as an age
// container sealed with passphrase, which is what 'age -p' writes.
func passphraseContainer(t *testing.T, keyText, passphrase string) []byte {
	t.Helper()

	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		t.Fatalf("creating a passphrase recipient: %v", err)
	}

	// age derives the key of a container for about a second by default, which a
	// test does not need.
	recipient.SetWorkFactor(15)

	container := bytes.Buffer{}
	if err := ageutil.Encrypt(strings.NewReader(keyText), &container, recipient); err != nil {
		t.Fatalf("encrypting identities to a passphrase: %v", err)
	}

	return container.Bytes()
}
