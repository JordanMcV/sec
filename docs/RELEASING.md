# Publishing with Homebrew

Start with a personal tap. It is a GitHub repository containing formulae; it
doesn't require acceptance into `homebrew/core`.

Keep the formula and executable named **`sec`**. An unrelated
[`sec` formula exists in Homebrew core](https://formulae.brew.sh/formula/sec), so
always document the fully qualified name **`JordanMcV/tap/sec`**. The tap selects
which formula to install; the two same-named formulae cannot be installed
side-by-side. See [duplicate formula names](https://docs.brew.sh/Taps#duplicate-names).

## Release checklist

1. Run `make test`, then complete the interactive hardware checks on a supported
   Mac: initialize, store a dummy value, release it to a child that only verifies
   it, cancel a release, and repeat after rebuilding/re-signing. Test multiple
   secrets and legacy migration too. Never use real credentials in release tests.
2. Choose a release version, update `Info.plist`, and commit the tested source.
   Tag that commit (for example `v0.2.0`) and publish a GitHub release. Do not move
   an existing release tag to different code.
3. Create a public GitHub repository named `JordanMcV/homebrew-tap`. Locally,
   `brew tap-new JordanMcV/tap` creates the tap structure and CI templates.
4. Create `Formula/sec.rb` in that tap. Point it at the release archive,
   download the archive, and calculate its SHA-256 with `shasum -a 256`. Use the
   real version and digest in the formula below; the placeholders aren't usable.

```ruby
class Sec < Formula
  desc "Release encrypted secrets to commands with Touch ID"
  homepage "https://github.com/JordanMcV/sec"
  url "https://github.com/JordanMcV/sec/archive/refs/tags/vRELEASE_VERSION.tar.gz"
  sha256 "RELEASE_ARCHIVE_SHA256"
  license "MIT"

  depends_on macos: :sonoma

  def install
    system "make", "install", "PREFIX=#{prefix}"
  end

  def caveats
    <<~EOS
      Requires Secure Enclave, enrolled Touch ID, and a local graphical session.
      Run `sec init` yourself after installation. Keep recovery copies of your
      credentials: changing enrolled fingerprints can invalidate the key.
    EOS
  end

  test do
    assert_match "sec init", shell_output("#{bin}/sec --help")
    assert_match "invalid environment variable",
                 shell_output("#{bin}/sec run BAD-NAME=example -- /usr/bin/true 2>&1", 1)
  end
end
```

5. Test the formula locally:

```sh
brew install --build-from-source JordanMcV/tap/sec
brew test JordanMcV/tap/sec
brew audit --strict --online JordanMcV/tap/sec
```

6. Commit and publish the tap, then add the installation command to the project
   README **once the package actually exists**:

```sh
brew install JordanMcV/tap/sec
sec init
```

`sec init` must never run during the formula build, installation, `post_install`,
or CI tests. It creates each user's key on their own Mac and requires their
biometric approval. Build artifacts must contain no generated keys or credentials.

Start with source builds using the Xcode Command Line Tools. Prebuilt Homebrew
packages ("bottles") can be added through the tap's CI later; verify the installed
binary's signature and the hardware flow after bottling. For each new release,
update the formula's archive URL and checksum; users then use `brew upgrade`.

`homebrew/core` submission is a separate option later. It requires a stable,
versioned, checksummed release and compliance with Homebrew's acceptance policy.
A working personal tap is enough to distribute the project now.

References: [Creating a tap](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap),
[Formula cookbook](https://docs.brew.sh/Formula-Cookbook), and
[Core requirements](https://docs.brew.sh/Acceptable-Formulae).
