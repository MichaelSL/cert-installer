# certinstall — design

Date: 2026-09-28
Status: reviewed (grill session 2026-09-28), awaiting approval

## Purpose

Developers testing HTTPS / WSS (websocket) endpoints locally use self-signed
certificates. Browsers reject them unless the certificate is in a trust store
the browser consults. `certinstall` is a small cross-platform CLI that adds,
removes and checks such a certificate in the right trust store, so
`https://` and `wss://` dev endpoints load without warnings.

Platform priority: Windows → macOS → Linux. On Linux, one browser
(Chrome/Chromium) is enough for the first version.

Target clients: Chrome/Edge (all OSes) and non-browser clients that read the
OS store (curl, OpenSSL, Go). Safari is covered incidentally by the macOS
keychain. Dev servers may present either a self-signed leaf or a leaf signed by
a local dev CA (in which case the CA is installed); the tool handles both.

## Non-goals (v1)

- Generating certificates or keys (the cert already exists; its path is an argument).
- Fetching certificates from a running server.
- Firefox profile NSS databases; Snap/Flatpak-sandboxed browsers.
- Anything other than one certificate per invocation.
- Managing runtime-specific trust (Node, Python): only guidance is printed.
- `list` / uninstall-by-fingerprint: certs are addressed by file only.
- Automatic elevation (sudo re-exec, UAC relaunch).
- Machine-readable output (`--json`) and `--quiet`.
- Code signing / notarization.

## CLI

```
certinstall install   <cert-file> [--system] [--force]
certinstall uninstall <cert-file> [--system]
certinstall status    <cert-file> [--system]
```

- `<cert-file>`: PEM (`.pem`, `.crt`) or DER (`.der`, `.cer`). A PEM file must
  contain exactly one `CERTIFICATE` block; other blocks (e.g. a private key) are
  ignored. Zero or multiple certificates → usage error.
- Default scope is the current user; `--system` targets the machine-wide store.
- `install` is idempotent: if already trusted, print so and exit 0.
- `uninstall` on a cert that is not installed prints so and exits 0.
- `status` prints `trusted` / `not trusted`.
- Output is human-readable text only: messages to stdout, warnings, errors and
  hints to stderr. Scripts rely on exit codes.

### Accepted certificates

- Self-signed (subject name == issuer name): accepted.
- CA certificate (basicConstraints CA=true): accepted.
- Leaf issued by another CA: refused with exit 2 —
  `this certificate is issued by <issuer>; install the issuing CA instead` —
  unless `--force` is given, in which case it is installed as-is.

### Privileges

The tool never elevates itself. `--system` without root/Administrator fails
with exit 3 and a hint (`re-run with sudo` / `re-run from an elevated
terminal`). `--system` means the machine store only; it never also touches a
user store.

### Linux: interactive system-wide prompt

On Linux, plain `install` (user scope) first installs into the NSS db, then —
if stdin and stdout are a TTY — asks `Also trust system-wide for curl/Go/OpenSSL? [y/N]`.
On `y`, if not root, it prints the exact command to run
(`sudo certinstall install --system <file>`) and exits 0 (the NSS install
succeeded). Without a TTY no prompt is shown; the tool behaves as user scope
and prints the same command as a hint.

### Post-install guidance

After a successful `install`, print how to make common runtimes use the cert,
since they ignore the OS store by default:

- Node: `NODE_EXTRA_CA_CERTS=<absolute path to cert>` or `node --use-system-ca`.
- Python requests: `REQUESTS_CA_BUNDLE=<path>` (replaces the bundle; point it at
  a combined bundle if other HTTPS is needed).
- Chrome on Linux: restart the browser.

The tool does not set environment variables itself.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success (`status`: trusted) |
| 1 | `status`: not trusted |
| 2 | Usage / input error (bad args, unreadable or invalid cert file) |
| 3 | Store operation failed (permissions, missing tool, user declined prompt) |

### Pre-install checks (warnings, do not block)

- Certificate is expired or not yet valid.
- Leaf certificate (not a CA) has no Subject Alternative Name — browsers ignore CN, so the cert
  will still be rejected even when trusted. This is the #1 cause of "trusted but
  still red".

### Identity

A certificate is identified by its SHA-256 fingerprint. Where a store needs a
name, it is `certinstall-<first 16 hex chars of SHA-256>` (the "nickname").

## Architecture

.NET 10, C#. Solution `CertInstaller.slnx`:

```
src/CertInstaller.Cli/        entry point, hand-rolled arg parsing (no deps, trim-safe), exit codes
src/CertInstaller.Core/
  CertificateFile.cs          load PEM/DER, fingerprints, validity + SAN checks
  ITrustStore.cs              Install / Uninstall / IsTrusted
  TrustStoreFactory.cs        picks implementation by OS + scope
  Stores/WindowsTrustStore.cs
  Stores/MacKeychainTrustStore.cs
  Stores/LinuxNssTrustStore.cs
  Stores/LinuxSystemTrustStore.cs
  Process/IProcessRunner.cs   runs external commands (fakeable in tests)
  Process/ProcessRunner.cs
  TrustStoreException.cs      carries an actionable hint for the user
tests/CertInstaller.Tests/    xUnit
```

```csharp
public enum Scope { User, System }

public interface ITrustStore
{
    void Install(CertificateFile cert);    // idempotent
    void Uninstall(CertificateFile cert);  // no-op if absent
    bool IsTrusted(CertificateFile cert);
}
```

`TrustStoreFactory.Create(Scope)` uses `OperatingSystem.IsWindows()/IsMacOS()/IsLinux()`.
Unsupported OS → exit 3 with a message.

`IProcessRunner.Run(string file, IReadOnlyList<string> args) → (int ExitCode, string StdOut, string StdErr)`;
arguments are passed as an argument list, never a concatenated shell string.

## Backends

### Windows — `WindowsTrustStore`

- `X509Store(StoreName.Root, StoreLocation.CurrentUser | LocalMachine)`, no external tools.
- Install: open ReadWrite, `Add`. For CurrentUser, Windows shows a security
  confirmation dialog; if declined, the add throws → exit 3 "declined".
- LocalMachine without elevation → `CryptographicException` → exit 3 with
  "re-run from an elevated (Administrator) terminal".
- Uninstall: find by thumbprint, `Remove`.
- IsTrusted: `Certificates.Find(X509FindType.FindByThumbprint, sha1, validOnly: false)` non-empty.

### macOS — `MacKeychainTrustStore`

.NET's `X509Store` cannot write trust settings to Root on macOS, so shell out to `/usr/bin/security`.

| Scope | Keychain | Trust domain |
|-------|----------|--------------|
| User | `~/Library/Keychains/login.keychain-db` | user (GUI password prompt) |
| System | `/Library/Keychains/System.keychain` | admin (`-d`), requires sudo |

- Install: `security add-trusted-cert [-d] -r <result> -k <keychain> <file>`,
  where `<result>` is `trustRoot` for self-signed certs and `trustAsRoot` for a
  `--force`d CA-issued leaf.
- Uninstall: `security remove-trusted-cert [-d] <file>`, then
  `security delete-certificate -Z <SHA-1> <keychain>`.
- IsTrusted: `security find-certificate -a -Z <keychain>` lists the SHA-1
  (present in this scope's keychain) AND `security verify-cert -c <file>` exits 0.
  (To be confirmed on a real Mac during manual testing.)
- System scope without root → exit 3 "re-run with sudo".

### Linux user scope — `LinuxNssTrustStore` (Chrome/Chromium)

- DB: `sql:$HOME/.pki/nssdb`. If missing, create it:
  `certutil -d sql:<db> -N --empty-password`.
- Requires NSS `certutil`. If not on PATH → exit 3 with
  "install libnss3-tools (Debian/Ubuntu), nss-tools (Fedora), nss (Arch)".
- Trust flags: `C,,` if the cert is a CA (basicConstraints CA=true),
  otherwise `P,,` (trusted peer — correct for a self-signed leaf).
- Install: `certutil -d sql:<db> -A -t <flags> -n <nickname> -i <file>`.
- Uninstall: `certutil -d sql:<db> -D -n <nickname>`.
- IsTrusted: `certutil -d sql:<db> -L -n <nickname>` exit 0.
- User must restart the browser after install.

### Linux system scope — `LinuxSystemTrustStore`

Covers curl, OpenSSL-based tools, Node, etc. (not necessarily Chrome).

| Distro family | Detected by | Anchor path | Refresh |
|---------------|-------------|-------------|---------|
| Debian/Ubuntu | `update-ca-certificates` on PATH | `/usr/local/share/ca-certificates/<nickname>.crt` | `update-ca-certificates` |
| Fedora/RHEL/Arch | `update-ca-trust` on PATH | `/etc/pki/ca-trust/source/anchors/<nickname>.pem` | `update-ca-trust extract` |

- The file is always written as PEM.
- Not root → exit 3 "re-run with sudo".
- Uninstall: delete the anchor file, run refresh.
- IsTrusted: anchor file exists and its content matches the cert.

## Error handling

Every store failure raises `TrustStoreException(message, hint)`. The CLI prints
`error: <message>` and, if present, `hint: <hint>` to stderr, exit 3. Input
errors (file missing, not a certificate) exit 2. No stack traces unless
`CERTINSTALL_DEBUG=1`.

## Packaging

Self-contained, single-file, trimmed publish per RID, all buildable from Linux:

```
dotnet publish src/CertInstaller.Cli -c Release -r <rid> --self-contained \
  -p:PublishSingleFile=true -p:PublishTrimmed=true -o dist/<rid>
```

RIDs: `win-x64`, `osx-arm64`, `osx-x64`, `linux-x64`, `linux-arm64`.
Assembly name `certinstall`. A `scripts/publish.sh` loops over the RIDs.
NativeAOT is not used (no cross-OS compilation).

Distribution: GitHub Releases. A workflow triggered by a `v*` tag publishes
all RIDs, packages each as `certinstall-<version>-<rid>.zip` (`.tar.gz` for
macOS/Linux to keep the executable bit) and attaches a `SHA256SUMS` file.
macOS archives are built on a macOS runner: the SDK only ad-hoc signs the
apphost when publishing on macOS, and unsigned arm64 binaries are killed.

Binaries are unsigned in v1. The README documents the workarounds: Windows
SmartScreen "More info → Run anyway"; macOS `xattr -d com.apple.quarantine certinstall`.

## Testing

- Unit tests (default `dotnet test`): certificate parsing (PEM, DER, multiple
  certs, garbage, SAN/expiry detection, CA detection), nickname derivation, and
  each shell-out backend's exact command lines via a fake `IProcessRunner`.
  Unit tests never touch a real trust store.
- Real-store testing is manual, on real machines on real machines (Windows PC, Mac,
  Linux desktop) before each release, following a checklist in
  `docs/manual-test-checklist.md`: install → Chrome loads a `wss://` test page
  without warning → status → uninstall → warning is back. Both scopes.
- CI (GitHub Actions, `windows-latest`, `macos-latest`, `ubuntu-latest`) runs
  unit tests only, plus the release workflow.

## Open questions

- Exact macOS `IsTrusted` command — confirm on a real Mac during manual testing.
