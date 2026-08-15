# sec

Hand a secret to a child process on macOS without ever printing it.

`sec` stores secrets in the login Keychain and injects them into the environment
of one command. No subcommand writes a secret value to stdout.

## Why

Coding agents, CI runners, and terminal scrollback all capture stdout. A tool
that prints a secret puts that secret into a transcript. A tool that injects it
into a child process does not.

The storage backend matters less than the interface. `sec` is built around a
single rule: print names, never values.

## Install

Requires macOS and the Xcode Command Line Tools.

```sh
make install          # builds and installs to ~/.local/bin/sec
```

## Use

Store a secret. The value is read from stdin, never from `argv`, because
arguments are visible to any user through `ps`.

```sh
printf %s 'your-api-key' | sec set komodo-api-key
```

Run a command with the secret in its environment:

```sh
sec run komodo-api-key -- \
  sh -c 'curl -sS -H "X-Api-Key: $KOMODO_API_KEY" https://komodo.example/read'
```

Use single quotes around the inner command. Double quotes make the outer shell
expand the variable first. That breaks the call and writes the value into shell
history.

The variable name is derived from the secret name. `komodo-api-key` becomes
`KOMODO_API_KEY`. Choose a different name with `VAR=name`:

```sh
sec run TOKEN=komodo-api-key -- ./deploy.sh
```

Pass several secrets at once:

```sh
sec run komodo-api-key komodo-api-secret -- ./publish.sh
```

Other commands:

```sh
sec list              # names and their variable names, never values
sec rm komodo-api-key
```

## Touch ID

`sec run` asks for Touch ID before it releases a secret.

This gate is **advisory**. The Keychain item is a standard generic password and
is not cryptographically bound to biometry. The prompt proves that a human
approved the read. It does not stop another process running as the same user
from reading the item directly with the Security framework.

That is a deliberate trade. An advisory gate needs no code signing identity, no
entitlements, and no Apple Developer account. See "Bound gate" below for the
stronger design.

Set `SEC_SKIP_BIOMETRY=1` to bypass the prompt for scripts and CI.

### Bundle identity

`LocalAuthentication` will not present the Touch ID dialog to a process that has
no bundle identifier and no code signature. There is no `.app` bundle here, so
the `Makefile` embeds `Info.plist` into the Mach-O at link time and then signs
the result. Removing either step breaks the prompt.

## Bound gate

A bound gate is one the hardware enforces. Two designs work:

**Access control on the item.** Store the secret in the data protection keychain
with `SecAccessControlCreateWithFlags(..., .biometryCurrentSet, ...)`. The
Keychain refuses to release the bytes without a matching fingerprint. On macOS
these items are scoped by keychain access group, which normally derives from a
Team ID, so this route can require a real Apple Developer identity.

**Secure Enclave key wrapping.** Generate a P-256 key in the Secure Enclave with
access control `[.privateKeyUsage, .biometryCurrentSet]`. Encrypt the secret to
its public key and store only the ciphertext. Decryption needs the Enclave key,
and using that key needs your fingerprint.

The second design is stronger in practice. Its security does not depend on
keychain access group scoping, so the ciphertext can sit in a readable file
without risk. It also works with a self-signed certificate.

Neither route needs a certificate issued by Apple. Both need a *stable* signing
identity. Ad-hoc signing derives the identity from the binary contents, so it
changes on every rebuild and orphans previously stored items. A self-signed code
signing certificate, created locally in Keychain Access, solves that for free.

A bound gate has a real cost: there is no bypass. Touch ID does not work over
SSH or on a headless machine. If you drive this tool remotely, keep the advisory
gate.

## Limitations

- macOS only. It depends on the Keychain and LocalAuthentication.
- Secrets must be valid UTF-8, because environment variables are strings.
- No caching. Every `sec run` prompts. There is no `sudo`-style timeout, because
  a `LAContext` reuse window cannot span separate processes.
- An advisory gate is not a security boundary against code running as you.

## Licence

MIT
