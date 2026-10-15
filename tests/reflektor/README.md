# Reflektor compatibility smoke test

This harness executes the repository-built Windows `amd64` and `386` COFF
objects with Reflektor `v0.0.7`, using the same default `go`/`_go` entrypoint
discovery as Sliver. It covers a zero-field argument buffer plus the typed
string encodings Sliver sends for the omitted/default option, `/cookies`,
`/all`, and an invalid-mode rejection. The successful cases assert distinct
mode output before the no-profile guard, so the smoke test also proves that
each packed option reaches the intended extraction branch. Oversized and
malformed present argument fields must fail closed instead of silently using
the default password-only mode.

The test intentionally provides no custom symbol resolver. This matches
Sliver's built-in Reflektor BOF handler and rejects any Beacon callback that
would require host support. It also requires every emitted record to use
`OutputDefault`; the records are concatenated and checked against the stable
no-profile result.

## Credential-safety boundary

Before Reflektor loads the object, the harness checks the current user's Firefox
profile location and every profile location the BOF can enumerate below
`C:\Users`. If any Firefox `Profiles` root exists, the harness stops without
executing the BOF. The GitHub Actions job uses a fresh hosted runner and never
uploads a profile or credential fixture.

This is deliberately a no-profile smoke test. It validates COFF loading, symbol
resolution, Beacon argument parsing, both native x86 execution paths, and output
callbacks. It does **not** test NSS loading, SQLite rows, DPAPI, master-password
handling, or decryption of actual Firefox data. Those operations cannot be
covered by a package CI job without introducing credential-like fixtures and a
substantially larger trusted runtime surface.

After this smoke test passes on each Windows runner, the same workflow runs
`sliver-test-bof` against Sliver session and beacon implants. Its manifest sends
only a nonempty invalid mode, which the BOF rejects before loading SQLite or
accessing Firefox profiles. This checks the Sliver/Reflektor BOF and argument
path without extracting profile data.
