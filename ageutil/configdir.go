package ageutil

import (
	"errors"
	"fmt"
	"path/filepath"
)

// xdgConfigDir returns the per-user configuration directory the way the XDG
// base directory spec defines it: XDG_CONFIG_HOME when the environment sets it,
// and the .config folder of the home directory otherwise. A variable that is
// set but empty counts as unset, as the spec and os.Getenv both treat it, and a
// relative one is refused, as os.UserConfigDir refuses it on the unixes, so that
// a private key is never looked for relative to the directory of a repository.
// env is the environment to read, so that the rule can be checked without a test
// having to change the one it runs within.
func xdgConfigDir(env func(string) string, home string) (string, error) {
	if config := env("XDG_CONFIG_HOME"); config != "" {
		if !filepath.IsAbs(config) {
			return "", fmt.Errorf("XDG_CONFIG_HOME is not an absolute path: %q", config)
		}

		return config, nil
	}

	if home == "" {
		return "", errors.New("neither XDG_CONFIG_HOME nor a home directory is set")
	}

	return filepath.Join(home, ".config"), nil
}
