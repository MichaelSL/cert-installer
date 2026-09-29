# certinstall

A small cross-platform CLI that installs, uninstalls and checks a self-signed
(or dev CA) certificate in the OS / browser trust store, so developers can open
the `https://` and `wss://` endpoints of a dev environment without browser
warnings.

> **Status:** early development. Certificate loading is implemented; the CLI
> commands and trust-store backends described below are being built.

## What it does

A typical setup: a dev environment is served at `dev1.my-dev.io`,
`dev2.my-dev.io`, … behind a self-signed certificate for `my-dev.io` (with
`*.my-dev.io` in its Subject Alternative Names). Browsers reject that
certificate until it is in a trust store they consult. Each developer runs
`certinstall install my-dev.io.crt` once, and every dev environment on that
domain then loads without warnings.

`certinstall` puts the certificate into the right store for the platform and
can take it out again:

| Platform | User scope (default) | System scope (`--system`) |
|----------|----------------------|---------------------------|
| Windows | `CurrentUser\Root` certificate store | `LocalMachine\Root` (elevated terminal) |
| macOS | login keychain, trusted as root | System keychain (`sudo`) |
| Linux | Chrome/Chromium NSS db (`~/.pki/nssdb`) | OS CA bundle via `update-ca-certificates` / `update-ca-trust` (`sudo`) |

It covers Chrome/Edge on all OSes, Safari on macOS, and non-browser clients that
read the OS store (curl, OpenSSL, Go).

It accepts a self-signed certificate or a CA certificate. A leaf issued by some
other CA is refused (install the issuing CA instead) unless you pass `--force`.

Before installing it warns — without blocking — when the certificate is expired
or not yet valid, or when a leaf certificate has no Subject Alternative Name
(browsers ignore the CN, so such a cert stays untrusted even when installed —
make sure the SANs cover the hosts developers visit, e.g. `*.my-dev.io`).

**Not in scope:** generating certificates, fetching them from a server, Firefox
profiles, Snap/Flatpak browsers, or elevating privileges for you.

## Usage

### Install

Download the archive for your platform from
[GitHub Releases](https://github.com/MichaelSL/cert-installer/releases)
(`certinstall-<version>-<rid>.zip` / `.tar.gz`, checksums in `SHA256SUMS`) and
put `certinstall` on your `PATH`. The binaries are self-contained — no .NET
runtime needed.

The binaries are not signed yet:

- **Windows:** on the SmartScreen prompt choose *More info → Run anyway*.
- **macOS:** `xattr -d com.apple.quarantine certinstall`

### Commands

```
certinstall install   <cert-file> [--system] [--force]
certinstall uninstall <cert-file> [--system]
certinstall status    <cert-file> [--system]
```

- `<cert-file>` — PEM (`.pem`, `.crt`) or DER (`.der`, `.cer`). A PEM file must
  contain exactly one `CERTIFICATE` block; other blocks such as a private key
  are ignored.
- `--system` — use the machine-wide store instead of the current user's. Needs
  `sudo` / an Administrator terminal; the tool never elevates itself.
- `--force` — install a leaf certificate issued by another CA as-is.

`install` and `uninstall` are idempotent. `status` prints `trusted` or
`not trusted`.

### Examples

```bash
# Trust the dev environment certificate for the current user
certinstall install ./my-dev.io.crt

# Check it — then https://dev1.my-dev.io loads without a warning
certinstall status ./my-dev.io.crt

# Trust it machine-wide (Linux/macOS), e.g. for curl and other CLI tools
sudo certinstall install --system ./my-dev.io.crt

# Remove it
certinstall uninstall ./my-dev.io.crt
```

On Linux, a user-scope `install` run in a terminal also offers to trust the
certificate system-wide and prints the `sudo` command to do so. Restart Chrome
after installing on Linux.

### Runtimes that ignore the OS store

After installing, `certinstall` prints hints for these; it does not set them for
you:

- **Node:** `NODE_EXTRA_CA_CERTS=/abs/path/my-dev.io.crt` or `node --use-system-ca`
- **Python requests:** `REQUESTS_CA_BUNDLE=/abs/path/bundle.pem` (replaces the
  default bundle)

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (`status`: trusted) |
| 1 | `status`: not trusted |
| 2 | Usage / input error (bad arguments, unreadable or invalid certificate) |
| 3 | Store operation failed (permissions, missing tool, prompt declined) |

Errors go to stderr as `error: …` followed by a `hint: …` where one helps.
Set `CERTINSTALL_DEBUG=1` to get stack traces.

## Development

### Prerequisites

- [.NET SDK 10](https://dotnet.microsoft.com/download) (pinned in
  [`global.json`](global.json), `10.0.100` or a later feature band)
- Linux: NSS `certutil` for the Chrome backend —
  `libnss3-tools` (Debian/Ubuntu), `nss-tools` (Fedora), `nss` (Arch)
- `zip` if you run the publish script for `win-x64`

### Set up and build

```bash
git clone git@github.com:MichaelSL/cert-installer.git
cd cert-installer
dotnet build
dotnet run --project src/CertInstaller.Cli -- status ./my-dev.io.crt
```

### Test

```bash
dotnet test                                   # unit tests; never touch a real trust store
dotnet test --filter Category=Integration     # modifies the REAL trust store
dotnet tool restore && dotnet stryker         # mutation testing -> StrykerOutput/
```

### Publish

```bash
./scripts/publish.sh <version> [rid...]
```

Builds self-contained, single-file, trimmed binaries and packages them as
`dist/certinstall-<version>-<rid>.zip|.tar.gz`. Default RIDs: `win-x64`,
`osx-arm64`, `osx-x64`, `linux-x64`, `linux-arm64`. Publish macOS RIDs on a Mac
— the SDK only ad-hoc signs the binary there, and unsigned arm64 binaries are
killed at launch.

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the unit tests
on Windows, macOS and Linux for every push and PR; each push to `main` also
publishes all RIDs and creates a GitHub Release versioned `YYYY.MM.<run number>`.

### Project layout

```
src/CertInstaller.Cli/     entry point, argument parsing, exit codes
src/CertInstaller.Core/    CertificateFile, ITrustStore + one store per OS/scope
tests/CertInstaller.Tests/ xUnit tests
scripts/                   publish helpers
```

Contribution rules (TDD, no shell strings, trim compatibility, exit-code
contract) are in [`AGENTS.md`](AGENTS.md).
