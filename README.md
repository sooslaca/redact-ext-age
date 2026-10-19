# age extension for Redact

This is a separate extension for [redact](https://github.com/julian7/redact), to store redact keys with [age](https://age-encryption.org).

It implements the standard extension interface:

- list
- get
- put
- grant
- revoke
- update

Parameters:

- agekey: age recipient (public key) of the Key Exchange collection to unlock with
- keyfile: age identity file to read the private key from, several separated with commas
- recipient: age recipient (public key) to grant access to, or to revoke
- file: age recipients file, one recipient per line

Usage:

- create an age key pair with `age-keygen`
- create an age key pair protected by a passphrase with `age-keygen -p -o IDENTITY`
- print the public key of an identity file with `age-keygen -y IDENTITY`
- grant access to the repository: `redact grant --ext age --option recipient=age1...`
- commit and push the changes, so that the other users get them
- unlock the repository: `redact unlock --ext age --option agekey=age1...`

The extension keeps the age-encrypted Key Exchange collections in the Key Exchange folder of the repository, as `.redact/<recipient>.agekey`. The name of such a file is the recipient its ciphertext grants access to, so the file is at once the collection and the registration of that recipient: granting writes the file, revoking removes it. It maintains the `*.agekey binary` entry of `.redact/.gitattributes` itself, so that git never converts the ciphertext.

The extension never uses the in-tree Key Exchange key: when no local age identity can unlock the collection, it reports that it is not applicable, and redact moves on to the other configured extensions.

The private key is read from `keyfile=PATH`, from the `AGE_IDENTITIES_FILE` environment variable, or from the per-user age identities file `~/.config/age/identities`, in this order. The `.config` part is the directory `XDG_CONFIG_HOME` names when the environment sets one, and the macOS build reads the key from there too, not from the `~/Library/Application Support` folder Go names on that system, so a key written on one system is found on another. If several local identities can unlock the repository, `get` lists the candidate recipients on stderr, without printing the collection, and asks for a second invocation with `agekey=`.

An identities file written by `age -p` or `age-keygen -p` keeps its private keys in an age container sealed with a passphrase. `get` asks for that passphrase on the controlling terminal, once per file, naming the file, and never on stdout, where redact reads the collection. What the user types is not repeated in a message.

- The passphrase that opens the file unlocks the repository with the identities it holds.
- A passphrase that was asked for and refused, wrong or empty, is reported as a failure, without printing the collection: the user was spoken to, and no other extension can answer that prompt better.
- A passphrase no terminal is there to type, and an identities file this extension cannot read at all, are reported on stderr and skipped, so that another identities file, or another redact extension, still unlocks the repository. `get` reports that it is not applicable when nothing contributed a private key.

## Licensing

SPDX-License-Identifier: BlueOak-1.0.0 OR MIT
