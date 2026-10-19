# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Unlock a repository with an identities file whose keys are protected by a
  passphrase, as `age -p` and `age-keygen -p` write one: `get` asks for the
  passphrase on the terminal, once per file, and never on stdout, where redact
  reads the collection. A passphrase that was asked for and refused is reported
  as a failure; a file whose passphrase there is no terminal to type, or that
  this extension cannot read at all, is reported on stderr and skipped, so that
  another identities file or another redact extension still unlocks the
  repository.

### Changed

- An age recipient is registered by the name of its encrypted collection alone:
  a grant writes `.redact/<recipient>.agekey`, and no longer the
  `.redact/<recipient>.agepub` registration file beside it, so granting three
  recipients adds three files instead of six. `list`, `update` and `revoke` read
  the recipient set from the names of the encrypted collections, and a file that
  carries the extension with a name that is not an age recipient is reported
  instead of taken for a registration. A repository granted by an earlier
  version needs no migration: revoking a recipient removes the registration
  file that version left behind.

[Unreleased]: https://github.com/sooslaca/redact-ext-age
