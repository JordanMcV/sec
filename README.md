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

That is a deliberate trade. An advisory gate needs no stable code signing
identity, no entitlements, and no Apple Developer account. See "Access models"
below for the stronger designs and what each one costs.

Set `SEC_SKIP_BIOMETRY=1` to bypass the prompt for scripts and CI.

### Bundle identity

`LocalAuthentication` will not present the Touch ID dialog to a process that has
no bundle identifier and no code signature. There is no `.app` bundle here, so
the `Makefile` embeds `Info.plist` into the Mach-O at link time and then signs
the result. Removing either step breaks the prompt.

## Access models

A Touch ID prompt can mean two different things. Confusing them leads to bad
design decisions, so this section separates them.

**Biometry as authorization.** The prompt proves a human is present, then the
data is released. The decryption key exists independently of your fingerprint.
Something else must stop an attacker from walking around the prompt.

**Biometry as part of the seal.** The key lives in the Secure Enclave, cannot be
exported by any mechanism, and the Enclave refuses to use it without a matching
fingerprint. There is no way around it. The bytes are unrecoverable without that
chip and that finger.

Apple Passwords uses the first kind. That is precisely why iCloud Keychain can
sync your passwords between devices while still asking for Touch ID. The items
are not hardware bound. What protects them is the keychain access group, which
stops code outside Apple's entitlements from querying them at all.

So the real trade is not "strong or portable". It is this:

| Model | Syncs | Enforced against local code | Cost |
| --- | --- | --- | --- |
| Advisory | Yes | No | Free |
| Access group | Yes | Yes, per team | Apple Developer Team ID |
| Secure Enclave | Never | Yes, by hardware | Free, self-signed |

`sec` ships the advisory model today.

Sync and hardware sealing are mutually exclusive. Only the access group model
gives both sync and enforcement, and it is the only model that costs money.

### Advisory

A standard generic password in the login keychain. The Touch ID prompt is a
presence check. Any process running as you can read the item directly through
the Security framework. The protection against transcript leaks comes from the
tool never printing a value, not from the Keychain.

### Rejected: legacy keychain ACLs

The file based keychain supports a per-item access control list naming the
binaries allowed to use an item, through `SecAccessCreate` and
`SecTrustedApplicationCreateFromPath`. On paper this gives per-item enforcement
with a self-signed certificate and no Team ID.

It was tested and rejected on two grounds.

Those APIs are deprecated. More importantly, they do not enforce reads. A test
on macOS 27 created an item whose ACL trusted only `/usr/bin/true`, then read it
from a different, untrusted, separately signed binary. The read succeeded and
returned the secret with no prompt, even with `kSecUseAuthenticationUI` set to
`kSecUseAuthenticationUIFail`, which converts any pending dialog into an error.

The ACL was not inert. Deleting the item from an untrusted binary failed with
"Invalid attempt to change the owner of this item". So the mechanism still
governs ownership and modification. It does not govern reads, and reads are the
operation that matters for a secret.

Do not use this route.

### Access group

The data protection keychain scopes items to an access group derived from your
Team ID. Only binaries signed by your team can query them. This is Apple's own
model, and it is the only one that syncs *and* enforces.

A Team ID is the specific thing an Apple Developer account buys here. A
self-signed certificate cannot claim one, so this tier genuinely requires the
paid membership.

### Secure Enclave

Generate a P-256 key in the Enclave with access control
`[.privateKeyUsage, .biometryCurrentSet]`. Encrypt the secret to its public key
and store only the ciphertext, which can sit in a world readable file without
risk. Decryption needs the Enclave key, and using that key needs your
fingerprint.

Strongest available without an Apple account. It can never sync: Enclave keys
are non-exportable by design, so ciphertext copied to another Mac is permanently
undecryptable there.

### Signing identity

Every model above the advisory tier needs a *stable* code signing identity.
Ad-hoc signing derives the identity from the binary contents, so it changes on
every rebuild and orphans anything bound to the previous identity. Create a
self-signed code signing certificate in Keychain Access and build with
`make SIGN_IDENTITY="your-cert-name"`.

### Choosing

If the goal is keeping secrets out of agent transcripts and CI logs, the
advisory model already achieves it, because the guarantee comes from the
interface rather than the store.

Choose a stronger model when the threat is other code running as your user.
Note that a hardware sealed gate has no bypass: Touch ID does not work over SSH
or on a headless machine.

## Limitations

- macOS only. It depends on the Keychain and LocalAuthentication.
- Secrets must be valid UTF-8, because environment variables are strings.
- No caching. Every `sec run` prompts. There is no `sudo`-style timeout, because
  a `LAContext` reuse window cannot span separate processes.
- An advisory gate is not a security boundary against code running as you.

## Licence

MIT
