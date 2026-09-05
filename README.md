# sec

Give a command access to your secrets without printing them in your terminal or
agent transcript. `sec` encrypts credentials locally and requires Touch ID to
decrypt them into a child process's environment.

## Install

Requires **macOS 14 or later**, a Mac with **Secure Enclave and enrolled Touch ID**,
and the Xcode Command Line Tools. Use a local graphical login session; SSH,
headless machines, and unattended CI are not supported for secret retrieval.

```sh
xcode-select --install  # if the Command Line Tools are not already installed
git clone https://github.com/JordanMcV/sec.git
cd sec
make install
```

The executable is installed to `~/.local/bin`. Add that directory to your shell's
`PATH` if necessary, then initialize your encryption key:

```sh
export PATH="$HOME/.local/bin:$PATH"
sec init
```

Setup generates and verifies a key on your Mac. No Apple Developer account or
personal signing certificate is needed. Running `sec init` again verifies the
existing key; it never replaces it.

## Use

Store a credential by piping it from a trusted source, such as your password
manager. `sec set` reads stdin, not a command-line argument. This is a dummy
example; don't type real credentials into shell history:

```sh
printf %s 'example-token' | sec set api-token
```

Run a command with the credential in its environment:

```sh
sec run api-token -- ./deploy.sh               # sets API_TOKEN
sec run TOKEN=api-token -- ./deploy.sh         # explicit variable name
sec run api-token api-secret -- ./deploy.sh    # multiple credentials
sec list                                      # names only
sec rm api-token                              # delete an encrypted entry
```

Approve Touch ID when prompted. `sec` decrypts the requested entries and replaces
itself with your command. Each invocation starts a fresh authentication context.
`set` also asks for Touch ID to verify that new ciphertext can be decrypted
before saving it. `list` and `rm` do not decrypt values.

For curl, pass the credential through stdin so it doesn't appear in curl's
process arguments:

```sh
sec run api-token -- \
  sh -c 'printf "Authorization: Bearer %s\n" "$API_TOKEN" |
    curl -sS --header @- https://api.example.com/resource'
```

Use single quotes around the child shell command so it expands the variable
after `sec` injects it. Your command must not log or print the credential.

Names such as `api-token` become `API_TOKEN`. Use `VAR=name` if the derived name
isn't a valid environment variable, or if two names would collide. Values must
be UTF-8 text without NUL bytes; trailing CR/LF characters are stripped on input.

## Security and recovery

- Credentials are encrypted with CryptoKit HPKE (P-256, HKDF-SHA256, AES-256-GCM).
  The private-key operation is protected by Secure Enclave and the currently
  enrolled fingerprints. Touch ID is enforced cryptographically, not by an
  advisory prompt. There is no password fallback or `SEC_SKIP_BIOMETRY` bypass.
- Only ciphertext and an encrypted, device-bound key representation are saved
  in the local Keychain. Secret names remain visible. Nothing syncs through
  iCloud, and copying these entries to another Mac cannot unlock them there.
- **Keep recovery copies in your password manager.** Adding or removing a
  fingerprint, losing the stored key, or erasing/replacing the Mac can make
  credentials unrecoverable. Before changing fingerprints, retain the original
  credentials so you can initialize fresh storage and import them again.
- Once approved, plaintext exists in process memory and the child's environment.
  Only run commands you trust. This does not sandbox the child, prevent another
  application from requesting biometric approval, or protect a compromised OS.

If the key is permanently unusable, recover your credentials from their original
source. To start over, remove the encrypted entries with `sec rm`, delete the
`default` entry with service `sec.enclave-key.v1` in Keychain Access, then run
`sec init` and re-import. This discards the old encrypted storage; it does not
recover it.

## Upgrading from the older Keychain backend

Old entries are not silently read or converted:

```sh
sec init
sec list
sec migrate api-token api-secret
```

Migration encrypts and verifies each copy without overwriting a conflicting
encrypted entry. **The old copies remain unprotected by Touch ID.** After testing
your commands, remove their entries with service **`sec`** in Keychain Access.
Do not remove **`sec.enclave-key.v1`** (your encryption key) or
**`sec.encrypted.v1`** (your encrypted credentials). `sec list` flags remaining
legacy copies; `sec rm` only removes encrypted entries.

## Development

```sh
make test
```

Automated tests use isolated storage and a test-only software key with the same
HPKE implementation; they never read your credentials or request Touch ID.
Hardware authentication must also be tested on a compatible Mac before release.

MIT licensed. See [LICENSE](LICENSE).
