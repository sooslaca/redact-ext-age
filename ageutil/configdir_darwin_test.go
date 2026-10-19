//go:build darwin

package ageutil

import (
	"path/filepath"
	"strings"
	"testing"
)

// An age key written on any system is found by the macOS build where it is kept
// on the other systems: the default identities file is the one below ~/.config,
// and not the one below the Application Support folder that os.UserConfigDir
// names on macOS, where no age key was ever written.
func TestDefaultIdentityFileUnderHome(t *testing.T) {
	home := t.TempDir()

	// Neither the identities file named by the environment nor one named by
	// XDG_CONFIG_HOME is there, so the per-user default below the home decides.
	t.Setenv("AGE_IDENTITIES_FILE", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)

	got := DefaultIdentityFile()

	want := filepath.Join(home, ".config", "age", "identities")
	if got != want {
		t.Errorf("DefaultIdentityFile() = %q, want %q", got, want)
	}

	if strings.Contains(got, "Library") {
		t.Errorf("DefaultIdentityFile() looks below the macOS Application Support folders: %q", got)
	}

	// XDG_CONFIG_HOME overrides the default here as it does on the unixes, where
	// os.UserConfigDir reads that variable itself.
	xdg := filepath.Join(home, "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)

	want = filepath.Join(xdg, "age", "identities")
	if got := DefaultIdentityFile(); got != want {
		t.Errorf("DefaultIdentityFile() with XDG_CONFIG_HOME = %q, want %q", got, want)
	}
}
