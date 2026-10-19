//go:build darwin

package ageutil

import "os"

// userConfigDir returns the directory the configuration of the user running the
// extension lives in. On macOS, os.UserConfigDir names ~/Library/Application
// Support and pays no attention to XDG_CONFIG_HOME, which leaves an age key kept
// under ~/.config, where every other platform looks for it, out of reach. The
// rule the unixes follow is applied here instead, so that one key works the same
// way wherever it was written.
func userConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return xdgConfigDir(os.Getenv, home)
}
