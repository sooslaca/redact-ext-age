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
- keyfile: age identity file to read the private key from
- recipient: age recipient (public key) to grant access to, or to revoke
- file: age recipients file, one recipient per line

Usage:

- create an age key pair with `age-keygen`
- print the public key of an identity file with `age-keygen -y IDENTITY`
- grant access to the repository: `redact grant --ext age --option recipient=age1...`
- commit and push the changes, so that the other users get them
- unlock the repository: `redact unlock --ext age --option agekey=age1...`

The extension keeps the age-encrypted Key Exchange collections and the recipient registrations in the Key Exchange folder of the repository, as `.redact/<recipient>.agekey` and `.redact/<recipient>.agepub`. It maintains the `*.agekey binary` entry of `.redact/.gitattributes` itself, so that git never converts the ciphertext.

The extension never uses the in-tree Key Exchange key: when no local age identity can unlock the collection, it reports that it is not applicable, and redact moves on to the other configured extensions.

The private key is read from `keyfile=PATH`, from the `AGE_IDENTITIES_FILE` environment variable, or from the per-user age identities file, in this order. If several local identities can unlock the repository, `get` lists the candidate recipients on stderr, without printing the collection, and asks for a second invocation with `agekey=`.

## Licensing

SPDX-License-Identifier: BlueOak-1.0.0 OR MIT
