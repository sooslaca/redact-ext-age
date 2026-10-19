//go:build !darwin

package ageutil

import "os"

// userConfigDir returns the directory the configuration of the user running the
// extension lives in. Off macOS, os.UserConfigDir already names what an age key
// is looked for in: XDG_CONFIG_HOME or ~/.config on the unixes, and %APPDATA%
// on Windows, where an age key is kept beside the configuration of the other
// tools rather than under a dot directory.
func userConfigDir() (string, error) {
	return os.UserConfigDir()
}
