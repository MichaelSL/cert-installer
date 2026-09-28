# certinstall — design

Date: 2026-09-28
Status: draft, awaiting review

## Purpose

Developers testing HTTPS / WSS (websocket) endpoints locally use self-signed
certificates. Browsers reject them unless the certificate is in a trust store
the browser consults. `certinstall` is a small cross-platform CLI that adds,
removes and checks such a certificate in the right trust store, so
`https://` and `wss://` dev endpoints load without warnings.

Platform priority: Windows → macOS → Linux. On Linux, one browser
(Chrome/Chromium) is enough for the first version.

## Non-goals (v1)

- Generating certificates or keys (the cert already exists; its path is an argument).
- Fetching certificates from a running server.
- Firefox profile NSS databases; Snap/Flatpak-sandboxed browsers.
- Anything other than one certificate per invocation.

## CLI

```
certinstall install   <cert-file> [--system]
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

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success (`status`: trusted) |
| 1 | `status`: not trusted |
| 2 | Usage / input error (bad args, unreadable or invalid cert file) |
| 3 | Store operation failed (permissions, missing tool, user declined prompt) |

### Pre-install checks (warnings, do not block)

- Certificate is expired or not yet valid.
- Certificate has no Subject Alternative Name — browsers ignore CN, so the cert
  will still be rejected even when trusted. This is the #1 cause of "trusted but
  still red".

### Identity

A certificate is identified by its SHA-256 fingerprint. Where a store needs a
name, it is `certinstall-<first 16 hex chars of SHA-256>` (the "nickname").

## Architecture

.NET 10, C#. Solution `CertInstaller.sln`:

```
src/CertInstaller.Cli/        entry point, System.CommandLine parsing, exit codes
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

- Install: `security add-trusted-cert [-d] -r trustRoot -p ssl -k <keychain> <file>`.
- Uninstall: `security remove-trusted-cert [-d] <file>`, then
  `security delete-certificate -Z <SHA-1> <keychain>`.
- IsTrusted: `security verify-cert -c <file> -p ssl` exit code 0. (To be
  confirmed on a real Mac during implementation; fallback is checking
  `security dump-trust-settings [-d]` for the SHA-1.)
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

RIDs: `win-x64`, `osx-arm64`, `osx-x64`, `linux-x64`. Assembly name `certinstall`.
A `scripts/publish.sh` loops over the RIDs. NativeAOT is not used (no cross-OS
compilation). macOS binaries are unsigned in v1; Gatekeeper quarantine can be
cleared with `xattr -d com.apple.quarantine`.

## Testing

- Unit tests (default `dotnet test`): certificate parsing (PEM, DER, multiple
  certs, garbage, SAN/expiry detection, CA detection), nickname derivation, and
  each shell-out backend's exact command lines via a fake `IProcessRunner`.
  Unit tests never touch a real trust store.
- Integration tests (`[Trait("Category","Integration")]`, excluded by default,
  run with `dotnet test --filter Category=Integration`): generate a throwaway
  self-signed cert, install → status → uninstall → status against the real store.
- CI: GitHub Actions matrix `windows-latest`, `macos-latest`, `ubuntu-latest`
  running unit tests everywhere, integration tests on Windows (CurrentUser)
  and Linux (NSS user + system via sudo), macOS system scope via sudo
  (user scope needs a GUI prompt).

## Open questions

- Exact macOS `IsTrusted` command — confirm on a real Mac.
- Whether the Windows CurrentUser Root confirmation dialog appears in CI
  (GitHub runners are known to allow it non-interactively; verify).
