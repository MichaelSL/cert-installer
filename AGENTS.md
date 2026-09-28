# AGENTS.md

Instructions for coding agents (Codex, Claude Code, etc.) working in this repo.

## Project

`certinstall` — a cross-platform CLI (.NET 10, C#) that installs, uninstalls and
checks a self-signed certificate in the OS / browser trust store, so local
`https://` and `wss://` dev endpoints are trusted by browsers.

Platform priority: Windows → macOS → Linux (Chrome/Chromium via NSS first).

Design spec: `docs/superpowers/specs/2026-09-28-certinstall-design.md` — read it
before making non-trivial changes and keep it in sync with behavior changes.

## Layout

- `src/CertInstaller.Cli/` — entry point, argument parsing, exit codes.
- `src/CertInstaller.Core/` — `CertificateFile`, `ITrustStore` and one
  implementation per OS/scope under `Stores/`, `IProcessRunner` for shell-outs.
- `tests/CertInstaller.Tests/` — xUnit tests.
- `scripts/` — publish helpers.

## Commands

```bash
dotnet build
dotnet test                                        # unit tests only
dotnet test --filter Category=Integration          # touches the REAL trust store
./scripts/publish.sh                               # self-contained binaries -> dist/<rid>/
```

## Rules

- Unit tests must never modify a real trust store. Use a fake `IProcessRunner`
  and assert on the exact command line. Real-store tests are integration tests
  tagged `[Trait("Category","Integration")]`.
- Keep all OS-specific code behind `ITrustStore`; the CLI and `CertificateFile`
  must be OS-agnostic.
- Invoke external tools with an argument list via `IProcessRunner` — never build
  shell command strings.
- Store failures throw `TrustStoreException` with an actionable hint
  (e.g. "re-run with sudo", "install libnss3-tools").
- Exit codes: 0 ok / trusted, 1 not trusted (`status`), 2 usage or input error,
  3 store operation failed. Don't change them without updating the spec.
- Keep the build trim-compatible (`PublishTrimmed=true`); no reflection-heavy
  dependencies. Nullable enabled, warnings as errors.
- Use test-driven development: write a failing test first.
