package ageutil

import (
	"testing"
)

// An age key is kept under ~/.config on the unixes, and the macOS build reads
// it from there too rather than from the Application Support folder
// os.UserConfigDir names on that system: the configuration directory is the one
// the XDG spec defines, with XDG_CONFIG_HOME as its override.
func TestXDGConfigDir(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		home string
		want string
	}{
		{
			name: "XDG_CONFIG_HOME names the directory",
			env:  map[string]string{"XDG_CONFIG_HOME": "/xdg/config"},
			home: "/home/user",
			want: "/xdg/config",
		},
		{
			name: "an absolute XDG_CONFIG_HOME is taken as it stands",
			env:  map[string]string{"XDG_CONFIG_HOME": "/home/user/.config"},
			home: "/home/user",
			want: "/home/user/.config",
		},
		{
			name: "home holds it when XDG_CONFIG_HOME is unset",
			env:  map[string]string{},
			home: "/home/user",
			want: "/home/user/.config",
		},
		{
			// os.Getenv cannot tell a variable that is set but empty from
			// one that is unset, and the spec reads both as unset.
			name: "home holds it when XDG_CONFIG_HOME is set but empty",
			env:  map[string]string{"XDG_CONFIG_HOME": ""},
			home: "/home/user",
			want: "/home/user/.config",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := func(key string) string { return test.env[key] }

			got, err := xdgConfigDir(env, test.home)
			if err != nil {
				t.Fatalf("configuration directory of home %q: %v", test.home, err)
			}

			if got != test.want {
				t.Errorf("configuration directory = %q, want %q", got, test.want)
			}
		})
	}
}

// What cannot name a directory of the user is refused rather than completed
// into a path: a default identities file built on an empty home would sit at the
// root of the filesystem, and a relative configuration directory would be read
// relative to the repository the extension was asked to unlock.
func TestXDGConfigDirRefused(t *testing.T) {
	for _, test := range []struct {
		name string
		env  map[string]string
		home string
	}{
		{name: "no home", env: map[string]string{}, home: ""},
		{name: "no home and an empty XDG_CONFIG_HOME", env: map[string]string{"XDG_CONFIG_HOME": ""}, home: ""},
		{name: "a relative XDG_CONFIG_HOME", env: map[string]string{"XDG_CONFIG_HOME": ".config"}, home: "/home/user"},
		{name: "a relative XDG_CONFIG_HOME without a home", env: map[string]string{"XDG_CONFIG_HOME": ".config"}, home: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := func(key string) string { return test.env[key] }

			dir, err := xdgConfigDir(env, test.home)
			if err == nil {
				t.Errorf("configuration directory returned %q and no error, want it refused", dir)
			}
		})
	}
}
