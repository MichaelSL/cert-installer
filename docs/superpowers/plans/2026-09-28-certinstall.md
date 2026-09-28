# certinstall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `certinstall`, a .NET 10 CLI that installs / uninstalls / checks one self-signed (or dev-CA) certificate in the OS or Chrome trust store on Windows, macOS and Linux.

**Architecture:** `CertInstaller.Core` holds `CertificateFile` (load + classify a cert), the `ITrustStore` abstraction with one implementation per OS/scope, and `IProcessRunner` for shelling out to `security` / `certutil` / `update-ca-*`. `CertInstaller.Cli` holds `CliApp` (argument parsing, flow, exit codes; fully testable with injected streams and a store factory) and a thin `Program.cs`. Shell-out backends are unit-tested by asserting exact command lines against a fake runner.

**Tech Stack:** .NET 10 SDK (10.0.x), C#, xUnit 2.9 (from `dotnet new xunit`), no other NuGet packages. GitHub Actions for CI and releases.

**Spec:** `docs/superpowers/specs/2026-09-28-certinstall-design.md` — read it before starting any task.

## Global Constraints

- Target framework `net10.0`; `global.json` pins SDK `10.0.100` with `rollForward: latestFeature`.
- `Nullable` enabled, `TreatWarningsAsErrors` true, `ImplicitUsings` enabled — set once in `Directory.Build.props`.
- No NuGet dependencies in `CertInstaller.Core` or `CertInstaller.Cli`. Must publish with `PublishTrimmed=true` without warnings.
- Executable name: `certinstall` (`AssemblyName` of the Cli project).
- Exit codes: `0` success / trusted, `1` not trusted (`status` only), `2` usage or input error, `3` store operation failed.
- Store nickname: `certinstall-<first 16 hex chars of SHA-256, lowercase>`.
- Output: results to stdout; lines prefixed `warning: `, `error: `, `hint: ` to stderr.
- Unit tests never modify a real trust store. External tools are only invoked via `IProcessRunner` with argument lists.
- Tests run on Windows, macOS and Linux CI: build expected paths with `Path.Combine`, never hard-coded `/`.
- Release RIDs: `win-x64`, `osx-arm64`, `osx-x64`, `linux-x64`, `linux-arm64`.

## Review Focus

1. A combined PEM (private key + certificate in one file, common for dev servers) → the certificate loads; the key is ignored. *(Task 1 test `Loads_pem_with_private_key_and_ignores_the_key`)*
2. A PEM edited on Windows (UTF-8 BOM, CRLF line endings) → loads. *(Task 1 test `Loads_pem_with_bom_and_crlf`)*
3. A relative path or a path with spaces → stores receive the absolute path, printed commands quote it. *(Task 1 `Relative_path_is_made_absolute`, Task 7 `Hint_quotes_path_with_spaces`)*
4. A Linux user who never opened Chrome (no `~/.pki/nssdb`, or an empty dir) → `install` creates the database; `status` says "not trusted" instead of failing. *(Task 3 tests `Install_creates_database_*`, `IsTrusted_false_without_database_and_runs_nothing`)*
5. The Linux "also system-wide?" prompt receiving EOF or a blank line → treated as "no", exit 0. *(Task 7 `Linux_interactive_blank_answer_does_nothing`)*

---

## File Structure

```
global.json
Directory.Build.props
CertInstaller.slnx
src/CertInstaller.Core/
  CertInstaller.Core.csproj
  CertificateFile.cs            load PEM/DER, fingerprints, nickname, classification, warnings
  CertificateLoadException.cs   input errors (-> exit 2)
  Scope.cs                      User | System
  ITrustStore.cs                Description / Install / Uninstall / IsTrusted
  TrustStoreException.cs        store errors with optional hint (-> exit 3)
  TrustStoreFactory.cs          picks store by OS + scope
  Process/IProcessRunner.cs     Run + CommandExists
  Process/ProcessResult.cs      ExitCode/StdOut/StdErr + EnsureSuccess
  Process/ProcessRunner.cs      real implementation
  Stores/LinuxNssTrustStore.cs
  Stores/LinuxSystemTrustStore.cs
  Stores/MacKeychainTrustStore.cs
  Stores/WindowsTrustStore.cs
src/CertInstaller.Cli/
  CertInstaller.Cli.csproj      AssemblyName=certinstall
  CliApp.cs                     parsing, flow, messages, exit codes
  CliEnvironment.cs             IsLinux / IsInteractive / IsPrivileged / Now
  Program.cs                    wires real console, env and factory
tests/CertInstaller.Tests/
  CertInstaller.Tests.csproj
  Support/TempDirectory.cs
  Support/TestCertificates.cs
  Support/FakeProcessRunner.cs
  Support/FakeTrustStore.cs
  CertificateFileTests.cs
  CertificateClassificationTests.cs
  ProcessRunnerTests.cs
  LinuxNssTrustStoreTests.cs
  LinuxSystemTrustStoreTests.cs
  MacKeychainTrustStoreTests.cs
  TrustStoreFactoryTests.cs
  CliAppTests.cs
scripts/publish.sh
.github/workflows/ci.yml
.github/workflows/release.yml
docs/manual-test-checklist.md
README.md
```

---

### Task 1: Solution scaffold and certificate loading

**Files:**
- Create: `global.json`, `Directory.Build.props`, `CertInstaller.slnx`, the three projects
- Create: `src/CertInstaller.Core/CertificateFile.cs`, `src/CertInstaller.Core/CertificateLoadException.cs`
- Create: `tests/CertInstaller.Tests/Support/TempDirectory.cs`, `tests/CertInstaller.Tests/Support/TestCertificates.cs`
- Test: `tests/CertInstaller.Tests/CertificateFileTests.cs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `namespace CertInstaller.Core`
  - `public sealed class CertificateLoadException(string message) : Exception`
  - `public sealed class CertificateFile` with `static CertificateFile Load(string path)`, properties `string Path` (absolute), `X509Certificate2 Certificate`, `string Sha256` (uppercase hex), `string Sha1` (uppercase hex), `string Nickname`, `string Subject`, `string Issuer`, method `string ToPem()`.
  - Test support (namespace `CertInstaller.Tests`): `TempDirectory : IDisposable` with `string Path`, `string Write(string name, string content)`, `string Write(string name, byte[] content)`; static `TestCertificates.SelfSignedLeaf(string[]? dnsNames = null, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)` returning `X509Certificate2` with private key, and extension `CertificateFile ToFile(this X509Certificate2 cert, TempDirectory dir, string name = "cert.pem")`.

- [ ] **Step 1: Scaffold the solution**

Run from the repo root:

```bash
cat > global.json <<'EOF'
{
  "sdk": {
    "version": "10.0.100",
    "rollForward": "latestFeature"
  }
}
EOF
cat > Directory.Build.props <<'EOF'
<Project>
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <LangVersion>latest</LangVersion>
  </PropertyGroup>
</Project>
EOF
dotnet new sln -n CertInstaller
dotnet new classlib -n CertInstaller.Core -o src/CertInstaller.Core
dotnet new console -n CertInstaller.Cli -o src/CertInstaller.Cli
dotnet new xunit -n CertInstaller.Tests -o tests/CertInstaller.Tests
rm src/CertInstaller.Core/Class1.cs tests/CertInstaller.Tests/UnitTest1.cs
dotnet sln CertInstaller.slnx add src/CertInstaller.Core src/CertInstaller.Cli tests/CertInstaller.Tests
dotnet add src/CertInstaller.Cli reference src/CertInstaller.Core
dotnet add tests/CertInstaller.Tests reference src/CertInstaller.Core src/CertInstaller.Cli
```

Then edit `src/CertInstaller.Cli/CertInstaller.Cli.csproj` so its `PropertyGroup` is exactly:

```xml
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <AssemblyName>certinstall</AssemblyName>
    <RootNamespace>CertInstaller.Cli</RootNamespace>
    <InvariantGlobalization>true</InvariantGlobalization>
    <IsTrimmable>true</IsTrimmable>
  </PropertyGroup>
```

Add `<IsTrimmable>true</IsTrimmable>` to the `PropertyGroup` of `src/CertInstaller.Core/CertInstaller.Core.csproj`. Leave the generated `TargetFramework`/`Nullable`/`ImplicitUsings` lines in the Core and Tests projects (they match the props file).

Run: `dotnet build`
Expected: `Build succeeded` with 0 warnings. (`dotnet new sln` on .NET 10 creates `CertInstaller.slnx`.)

- [ ] **Step 2: Add test support helpers**

`tests/CertInstaller.Tests/Support/TempDirectory.cs`:

```csharp
using System.Text;

namespace CertInstaller.Tests;

internal sealed class TempDirectory : IDisposable
{
    public string Path { get; } = Directory.CreateTempSubdirectory("certinstall-tests-").FullName;

    public string Write(string name, byte[] content)
    {
        var path = System.IO.Path.Combine(Path, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    public string Write(string name, string content) => Write(name, Encoding.UTF8.GetBytes(content));

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
```

`tests/CertInstaller.Tests/Support/TestCertificates.cs`:

```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertInstaller.Core;

namespace CertInstaller.Tests;

internal static class TestCertificates
{
    public static X509Certificate2 SelfSignedLeaf(
        string[]? dnsNames = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        AddSan(request, dnsNames ?? ["localhost"]);
        return request.CreateSelfSigned(
            notBefore ?? DateTimeOffset.UtcNow.AddDays(-1),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(30));
    }

    public static CertificateFile ToFile(this X509Certificate2 cert, TempDirectory dir, string name = "cert.pem") =>
        CertificateFile.Load(dir.Write(name, cert.ExportCertificatePem()));

    private static void AddSan(CertificateRequest request, string[] dnsNames)
    {
        if (dnsNames.Length == 0)
        {
            return;
        }

        var san = new SubjectAlternativeNameBuilder();
        foreach (var name in dnsNames)
        {
            san.AddDnsName(name);
        }

        request.CertificateExtensions.Add(san.Build());
    }
}
```

- [ ] **Step 3: Write the failing tests**

`tests/CertInstaller.Tests/CertificateFileTests.cs`:

```csharp
using System.Security.Cryptography;
using System.Text;
using CertInstaller.Core;

namespace CertInstaller.Tests;

public sealed class CertificateFileTests : IDisposable
{
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Loads_pem_certificate()
    {
        using var cert = TestCertificates.SelfSignedLeaf();
        var path = _dir.Write("cert.pem", cert.ExportCertificatePem());

        var file = CertificateFile.Load(path);

        Assert.Equal(cert.GetCertHashString(HashAlgorithmName.SHA256), file.Sha256);
        Assert.Equal(cert.Thumbprint, file.Sha1);
        Assert.Equal(path, file.Path);
        Assert.Equal("CN=localhost", file.Subject);
    }

    [Fact]
    public void Loads_der_certificate()
    {
        using var cert = TestCertificates.SelfSignedLeaf();
        var path = _dir.Write("cert.der", cert.RawData);

        var file = CertificateFile.Load(path);

        Assert.Equal(cert.GetCertHashString(HashAlgorithmName.SHA256), file.Sha256);
    }

    [Fact]
    public void Loads_pem_with_private_key_and_ignores_the_key()
    {
        using var cert = TestCertificates.SelfSignedLeaf();
        var keyPem = cert.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem();
        var path = _dir.Write("combined.pem", keyPem + "\n" + cert.ExportCertificatePem() + "\n");

        var file = CertificateFile.Load(path);

        Assert.Equal(cert.GetCertHashString(HashAlgorithmName.SHA256), file.Sha256);
        Assert.False(file.Certificate.HasPrivateKey);
    }

    [Fact]
    public void Loads_pem_with_bom_and_crlf()
    {
        using var cert = TestCertificates.SelfSignedLeaf();
        var text = cert.ExportCertificatePem().Replace("\n", "\r\n") + "\r\n";
        byte[] bytes = [.. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes(text)];
        var path = _dir.Write("windows.pem", bytes);

        var file = CertificateFile.Load(path);

        Assert.Equal(cert.GetCertHashString(HashAlgorithmName.SHA256), file.Sha256);
    }

    [Fact]
    public void Relative_path_is_made_absolute()
    {
        using var cert = TestCertificates.SelfSignedLeaf();
        var path = _dir.Write("cert.pem", cert.ExportCertificatePem());
        var relative = Path.GetRelativePath(Environment.CurrentDirectory, path);

        var file = CertificateFile.Load(relative);

        Assert.Equal(path, file.Path);
    }

    [Fact]
    public void Rejects_multiple_certificates()
    {
        using var first = TestCertificates.SelfSignedLeaf();
        using var second = TestCertificates.SelfSignedLeaf();
        var path = _dir.Write("two.pem", first.ExportCertificatePem() + "\n" + second.ExportCertificatePem() + "\n");

        var ex = Assert.Throws<CertificateLoadException>(() => CertificateFile.Load(path));

        Assert.Contains("2 certificates", ex.Message);
    }

    [Fact]
    public void Rejects_pem_without_certificate()
    {
        using var cert = TestCertificates.SelfSignedLeaf();
        var path = _dir.Write("key.pem", cert.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem());

        var ex = Assert.Throws<CertificateLoadException>(() => CertificateFile.Load(path));

        Assert.Contains("no CERTIFICATE block", ex.Message);
    }

    [Fact]
    public void Rejects_garbage()
    {
        var path = _dir.Write("garbage.der", new byte[] { 1, 2, 3, 4 });

        var ex = Assert.Throws<CertificateLoadException>(() => CertificateFile.Load(path));

        Assert.Contains("not a valid X.509 certificate", ex.Message);
    }

    [Fact]
    public void Rejects_missing_file()
    {
        var path = Path.Combine(_dir.Path, "missing.pem");

        var ex = Assert.Throws<CertificateLoadException>(() => CertificateFile.Load(path));

        Assert.Contains("file not found", ex.Message);
    }

    [Fact]
    public void Nickname_is_lowercase_sha256_prefix()
    {
        using var cert = TestCertificates.SelfSignedLeaf();
        var file = cert.ToFile(_dir);

        Assert.Equal("certinstall-" + file.Sha256[..16].ToLowerInvariant(), file.Nickname);
        Assert.Equal(28, file.Nickname.Length);
    }

    [Fact]
    public void ToPem_round_trips()
    {
        using var cert = TestCertificates.SelfSignedLeaf();
        var file = cert.ToFile(_dir);

        var reloaded = CertificateFile.Load(_dir.Write("again.pem", file.ToPem()));

        Assert.Equal(file.Sha256, reloaded.Sha256);
    }
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `dotnet test`
Expected: build FAILS with `CS0246: The type or namespace name 'CertificateFile' could not be found`.

- [ ] **Step 5: Implement**

`src/CertInstaller.Core/CertificateLoadException.cs`:

```csharp
namespace CertInstaller.Core;

public sealed class CertificateLoadException(string message) : Exception(message);
```

`src/CertInstaller.Core/CertificateFile.cs`:

```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertInstaller.Core;

public sealed class CertificateFile
{
    private CertificateFile(string path, X509Certificate2 certificate)
    {
        Path = path;
        Certificate = certificate;
        Sha256 = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        Sha1 = certificate.Thumbprint;
    }

    public string Path { get; }

    public X509Certificate2 Certificate { get; }

    public string Sha256 { get; }

    public string Sha1 { get; }

    public string Nickname => "certinstall-" + Sha256[..16].ToLowerInvariant();

    public string Subject => Certificate.Subject;

    public string Issuer => Certificate.Issuer;

    public string ToPem() => Certificate.ExportCertificatePem();

    public static CertificateFile Load(string path)
    {
        var fullPath = System.IO.Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new CertificateLoadException($"file not found: {fullPath}");
        }

        var bytes = File.ReadAllBytes(fullPath);
        var text = Encoding.UTF8.GetString(bytes);
        var der = text.Contains("-----BEGIN ", StringComparison.Ordinal)
            ? ExtractSinglePemCertificate(fullPath, text)
            : bytes;

        try
        {
            return new CertificateFile(fullPath, X509CertificateLoader.LoadCertificate(der));
        }
        catch (CryptographicException)
        {
            throw new CertificateLoadException($"not a valid X.509 certificate: {fullPath}");
        }
    }

    private static byte[] ExtractSinglePemCertificate(string path, string pem)
    {
        var certificates = new List<byte[]>();
        ReadOnlySpan<char> remaining = pem;
        while (PemEncoding.TryFind(remaining, out var fields))
        {
            if (remaining[fields.Label].Equals("CERTIFICATE", StringComparison.Ordinal))
            {
                certificates.Add(Convert.FromBase64String(remaining[fields.Base64Data].ToString()));
            }

            remaining = remaining[fields.Location.End.Value..];
        }

        return certificates.Count switch
        {
            0 => throw new CertificateLoadException($"no CERTIFICATE block found in {path}"),
            1 => certificates[0],
            _ => throw new CertificateLoadException(
                $"{path} contains {certificates.Count} certificates; pass one certificate per invocation"),
        };
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `dotnet test`
Expected: `Passed!  - Failed: 0, Passed: 11`

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: scaffold solution and load PEM/DER certificates"
```

---

### Task 2: Certificate classification and pre-install warnings

**Files:**
- Modify: `src/CertInstaller.Core/CertificateFile.cs`
- Modify: `tests/CertInstaller.Tests/Support/TestCertificates.cs`
- Test: `tests/CertInstaller.Tests/CertificateClassificationTests.cs`

**Interfaces:**
- Consumes: `CertificateFile`, `TestCertificates`, `TempDirectory` from Task 1.
- Produces:
  - `CertificateFile.IsCertificateAuthority` (`bool`, basicConstraints CA=true)
  - `CertificateFile.IsSelfSigned` (`bool`, subject name bytes == issuer name bytes)
  - `IReadOnlyList<string> CertificateFile.GetWarnings(DateTimeOffset now)` — messages without the `warning: ` prefix.
  - `TestCertificates.CertificateAuthority()` → CA cert with private key, valid now-2d..now+365d, no SAN.
  - `TestCertificates.LeafSignedBy(X509Certificate2 ca)` → leaf `CN=localhost` with SAN `localhost`, issued by `ca`.

- [ ] **Step 1: Add CA helpers to `TestCertificates`**

Add these methods inside `TestCertificates`:

```csharp
    public static X509Certificate2 CertificateAuthority()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=certinstall test CA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(365));
    }

    public static X509Certificate2 LeafSignedBy(X509Certificate2 ca)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        AddSan(request, ["localhost"]);
        return request.Create(
            ca,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30),
            [1, 2, 3, 4]);
    }
```

- [ ] **Step 2: Write the failing tests**

`tests/CertInstaller.Tests/CertificateClassificationTests.cs`:

```csharp
namespace CertInstaller.Tests;

public sealed class CertificateClassificationTests : IDisposable
{
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Self_signed_leaf_is_self_signed_and_not_ca()
    {
        var file = TestCertificates.SelfSignedLeaf().ToFile(_dir);

        Assert.True(file.IsSelfSigned);
        Assert.False(file.IsCertificateAuthority);
    }

    [Fact]
    public void Ca_is_self_signed_and_ca()
    {
        var file = TestCertificates.CertificateAuthority().ToFile(_dir);

        Assert.True(file.IsSelfSigned);
        Assert.True(file.IsCertificateAuthority);
    }

    [Fact]
    public void Ca_issued_leaf_is_neither()
    {
        using var ca = TestCertificates.CertificateAuthority();
        var file = TestCertificates.LeafSignedBy(ca).ToFile(_dir);

        Assert.False(file.IsSelfSigned);
        Assert.False(file.IsCertificateAuthority);
    }

    [Fact]
    public void Valid_leaf_with_san_has_no_warnings()
    {
        var file = TestCertificates.SelfSignedLeaf().ToFile(_dir);

        Assert.Empty(file.GetWarnings(DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Expired_certificate_warns()
    {
        var file = TestCertificates.SelfSignedLeaf(
            notBefore: DateTimeOffset.UtcNow.AddDays(-10),
            notAfter: DateTimeOffset.UtcNow.AddDays(-1)).ToFile(_dir);

        var warning = Assert.Single(file.GetWarnings(DateTimeOffset.UtcNow));
        Assert.Contains("expired", warning);
    }

    [Fact]
    public void Not_yet_valid_certificate_warns()
    {
        var file = TestCertificates.SelfSignedLeaf(
            notBefore: DateTimeOffset.UtcNow.AddDays(1),
            notAfter: DateTimeOffset.UtcNow.AddDays(30)).ToFile(_dir);

        var warning = Assert.Single(file.GetWarnings(DateTimeOffset.UtcNow));
        Assert.Contains("not valid until", warning);
    }

    [Fact]
    public void Leaf_without_san_warns()
    {
        var file = TestCertificates.SelfSignedLeaf(dnsNames: []).ToFile(_dir);

        var warning = Assert.Single(file.GetWarnings(DateTimeOffset.UtcNow));
        Assert.Contains("Subject Alternative Name", warning);
    }

    [Fact]
    public void Ca_without_san_has_no_warnings()
    {
        var file = TestCertificates.CertificateAuthority().ToFile(_dir);

        Assert.Empty(file.GetWarnings(DateTimeOffset.UtcNow));
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `dotnet test --filter FullyQualifiedName~CertificateClassificationTests`
Expected: build FAILS with `'CertificateFile' does not contain a definition for 'IsSelfSigned'`.

- [ ] **Step 4: Implement**

Add to `CertificateFile` (after `Issuer`):

```csharp
    public bool IsCertificateAuthority =>
        Certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority);

    public bool IsSelfSigned =>
        Certificate.SubjectName.RawData.AsSpan().SequenceEqual(Certificate.IssuerName.RawData);

    public IReadOnlyList<string> GetWarnings(DateTimeOffset now)
    {
        var warnings = new List<string>();
        var notBefore = Certificate.NotBefore.ToUniversalTime();
        var notAfter = Certificate.NotAfter.ToUniversalTime();

        if (now.UtcDateTime < notBefore)
        {
            warnings.Add($"certificate is not valid until {notBefore:u}");
        }

        if (now.UtcDateTime > notAfter)
        {
            warnings.Add($"certificate expired on {notAfter:u}");
        }

        if (!IsCertificateAuthority && !Certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().Any())
        {
            warnings.Add("certificate has no Subject Alternative Name; browsers ignore the Common Name and will reject it even when trusted");
        }

        return warnings;
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test`
Expected: `Passed!  - Failed: 0, Passed: 19`

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: classify certificates and warn on expiry or missing SAN"
```

---

### Task 3: Trust store abstractions, process runner, Linux NSS store

**Files:**
- Create: `src/CertInstaller.Core/Scope.cs`, `ITrustStore.cs`, `TrustStoreException.cs`
- Create: `src/CertInstaller.Core/Process/IProcessRunner.cs`, `ProcessResult.cs`, `ProcessRunner.cs`
- Create: `src/CertInstaller.Core/Stores/LinuxNssTrustStore.cs`
- Create: `tests/CertInstaller.Tests/Support/FakeProcessRunner.cs`
- Test: `tests/CertInstaller.Tests/ProcessRunnerTests.cs`, `tests/CertInstaller.Tests/LinuxNssTrustStoreTests.cs`

**Interfaces:**
- Consumes: `CertificateFile` (`Path`, `Nickname`, `IsCertificateAuthority`), `TestCertificates`, `TempDirectory`.
- Produces:
  - `public enum Scope { User, System }`
  - `public interface ITrustStore { string Description { get; } void Install(CertificateFile cert); void Uninstall(CertificateFile cert); bool IsTrusted(CertificateFile cert); }` — stores do **not** check "already installed"; `CliApp` does that via `IsTrusted`.
  - `public sealed class TrustStoreException(string message, string? hint = null) : Exception` with `string? Hint`.
  - `namespace CertInstaller.Core.Process`: `public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr)` with `void EnsureSuccess(string action)`; `public interface IProcessRunner { ProcessResult Run(string fileName, IReadOnlyList<string> arguments); bool CommandExists(string name); }`; `public sealed class ProcessRunner : IProcessRunner`.
  - `namespace CertInstaller.Core.Stores`: `public sealed class LinuxNssTrustStore(IProcessRunner runner, string homeDirectory) : ITrustStore`.
  - Test support: `FakeProcessRunner` with `HashSet<string> AvailableCommands`, `List<string> Calls` (each entry: file name and arguments joined by single spaces), `void Respond(string prefix, int exitCode, string stdout = "", string stderr = "")` (longest matching prefix wins; unmatched calls return exit 0 with empty output).

- [ ] **Step 1: Write the fake runner**

`tests/CertInstaller.Tests/Support/FakeProcessRunner.cs`:

```csharp
using CertInstaller.Core.Process;

namespace CertInstaller.Tests;

internal sealed class FakeProcessRunner : IProcessRunner
{
    private readonly Dictionary<string, ProcessResult> _responses = new();

    public HashSet<string> AvailableCommands { get; } = new();

    public List<string> Calls { get; } = new();

    public void Respond(string prefix, int exitCode, string stdout = "", string stderr = "") =>
        _responses[prefix] = new ProcessResult(exitCode, stdout, stderr);

    public ProcessResult Run(string fileName, IReadOnlyList<string> arguments)
    {
        var line = string.Join(' ', new[] { fileName }.Concat(arguments));
        Calls.Add(line);
        return _responses
            .Where(r => line.StartsWith(r.Key, StringComparison.Ordinal))
            .OrderByDescending(r => r.Key.Length)
            .Select(r => r.Value)
            .FirstOrDefault(new ProcessResult(0, "", ""));
    }

    public bool CommandExists(string name) => AvailableCommands.Contains(name);
}
```

- [ ] **Step 2: Write the failing tests**

`tests/CertInstaller.Tests/ProcessRunnerTests.cs`:

```csharp
using CertInstaller.Core;
using CertInstaller.Core.Process;

namespace CertInstaller.Tests;

public sealed class ProcessRunnerTests
{
    private readonly ProcessRunner _runner = new();

    [Fact]
    public void Runs_command_and_captures_stdout()
    {
        var result = _runner.Run("dotnet", ["--version"]);

        Assert.Equal(0, result.ExitCode);
        Assert.StartsWith("10.", result.StdOut.Trim());
    }

    [Fact]
    public void Missing_executable_throws_trust_store_exception()
    {
        var ex = Assert.Throws<TrustStoreException>(() => _runner.Run("certinstall-no-such-tool", []));

        Assert.Contains("certinstall-no-such-tool", ex.Message);
    }

    [Fact]
    public void CommandExists_finds_dotnet_on_path()
    {
        Assert.True(_runner.CommandExists("dotnet"));
        Assert.False(_runner.CommandExists("certinstall-no-such-tool"));
    }

    [Fact]
    public void EnsureSuccess_throws_with_stderr_on_failure()
    {
        var ex = Assert.Throws<TrustStoreException>(
            () => new ProcessResult(1, "", "  bad thing\n").EnsureSuccess("do the thing"));

        Assert.Equal("failed to do the thing: bad thing", ex.Message);
    }

    [Fact]
    public void EnsureSuccess_passes_on_zero_exit()
    {
        new ProcessResult(0, "", "").EnsureSuccess("do the thing");
    }
}
```

`tests/CertInstaller.Tests/LinuxNssTrustStoreTests.cs`:

```csharp
using CertInstaller.Core;
using CertInstaller.Core.Stores;

namespace CertInstaller.Tests;

public sealed class LinuxNssTrustStoreTests : IDisposable
{
    private readonly TempDirectory _home = new();
    private readonly TempDirectory _certs = new();
    private readonly FakeProcessRunner _runner = new();
    private readonly string _dbDirectory;
    private readonly string _db;

    public LinuxNssTrustStoreTests()
    {
        _runner.AvailableCommands.Add("certutil");
        _dbDirectory = Path.Combine(_home.Path, ".pki", "nssdb");
        _db = "sql:" + _dbDirectory;
    }

    public void Dispose()
    {
        _home.Dispose();
        _certs.Dispose();
    }

    private LinuxNssTrustStore Store => new(_runner, _home.Path);

    private CertificateFile Leaf() => TestCertificates.SelfSignedLeaf().ToFile(_certs);

    private void CreateExistingDatabase()
    {
        Directory.CreateDirectory(_dbDirectory);
        File.WriteAllText(Path.Combine(_dbDirectory, "cert9.db"), "");
    }

    [Fact]
    public void Install_self_signed_leaf_as_trusted_peer()
    {
        CreateExistingDatabase();
        var file = Leaf();

        Store.Install(file);

        Assert.Equal(new[] { $"certutil -d {_db} -A -t P,, -n {file.Nickname} -i {file.Path}" }, _runner.Calls);
    }

    [Fact]
    public void Install_ca_as_trusted_ca()
    {
        CreateExistingDatabase();
        var file = TestCertificates.CertificateAuthority().ToFile(_certs);

        Store.Install(file);

        Assert.Equal(new[] { $"certutil -d {_db} -A -t C,, -n {file.Nickname} -i {file.Path}" }, _runner.Calls);
    }

    [Fact]
    public void Install_creates_database_when_missing()
    {
        var file = Leaf();

        Store.Install(file);

        Assert.True(Directory.Exists(_dbDirectory));
        Assert.Equal(2, _runner.Calls.Count);
        Assert.Equal($"certutil -d {_db} -N --empty-password", _runner.Calls[0]);
    }

    [Fact]
    public void Install_creates_database_when_directory_is_empty()
    {
        Directory.CreateDirectory(_dbDirectory);

        Store.Install(Leaf());

        Assert.Equal($"certutil -d {_db} -N --empty-password", _runner.Calls[0]);
    }

    [Fact]
    public void Install_fails_with_hint_when_certutil_missing()
    {
        _runner.AvailableCommands.Clear();

        var ex = Assert.Throws<TrustStoreException>(() => Store.Install(Leaf()));

        Assert.Contains("libnss3-tools", ex.Hint);
        Assert.Empty(_runner.Calls);
    }

    [Fact]
    public void Install_reports_certutil_failure()
    {
        CreateExistingDatabase();
        _runner.Respond("certutil", 1, stderr: "SEC_ERROR_BAD_DATABASE");

        var ex = Assert.Throws<TrustStoreException>(() => Store.Install(Leaf()));

        Assert.Contains("SEC_ERROR_BAD_DATABASE", ex.Message);
    }

    [Fact]
    public void Uninstall_deletes_by_nickname()
    {
        CreateExistingDatabase();
        var file = Leaf();

        Store.Uninstall(file);

        Assert.Equal(new[] { $"certutil -d {_db} -D -n {file.Nickname}" }, _runner.Calls);
    }

    [Fact]
    public void IsTrusted_lists_by_nickname()
    {
        CreateExistingDatabase();
        var file = Leaf();

        Assert.True(Store.IsTrusted(file));
        Assert.Equal(new[] { $"certutil -d {_db} -L -n {file.Nickname}" }, _runner.Calls);
    }

    [Fact]
    public void IsTrusted_false_when_nickname_not_found()
    {
        CreateExistingDatabase();
        _runner.Respond("certutil", 255, stderr: "could not find certificate named");

        Assert.False(Store.IsTrusted(Leaf()));
    }

    [Fact]
    public void IsTrusted_false_without_database_and_runs_nothing()
    {
        Assert.False(Store.IsTrusted(Leaf()));
        Assert.Empty(_runner.Calls);
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `dotnet test`
Expected: build FAILS with `CS0234: The type or namespace name 'Process' does not exist in the namespace 'CertInstaller.Core'`.

- [ ] **Step 4: Implement abstractions**

`src/CertInstaller.Core/Scope.cs`:

```csharp
namespace CertInstaller.Core;

public enum Scope
{
    User,
    System,
}
```

`src/CertInstaller.Core/ITrustStore.cs`:

```csharp
namespace CertInstaller.Core;

public interface ITrustStore
{
    string Description { get; }

    void Install(CertificateFile cert);

    void Uninstall(CertificateFile cert);

    bool IsTrusted(CertificateFile cert);
}
```

`src/CertInstaller.Core/TrustStoreException.cs`:

```csharp
namespace CertInstaller.Core;

public sealed class TrustStoreException(string message, string? hint = null) : Exception(message)
{
    public string? Hint { get; } = hint;
}
```

`src/CertInstaller.Core/Process/ProcessResult.cs`:

```csharp
namespace CertInstaller.Core.Process;

public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr)
{
    public void EnsureSuccess(string action)
    {
        if (ExitCode != 0)
        {
            throw new TrustStoreException($"failed to {action}: {StdErr.Trim()}");
        }
    }
}
```

`src/CertInstaller.Core/Process/IProcessRunner.cs`:

```csharp
namespace CertInstaller.Core.Process;

public interface IProcessRunner
{
    ProcessResult Run(string fileName, IReadOnlyList<string> arguments);

    bool CommandExists(string name);
}
```

`src/CertInstaller.Core/Process/ProcessRunner.cs`:

```csharp
using System.ComponentModel;
using System.Diagnostics;

namespace CertInstaller.Core.Process;

public sealed class ProcessRunner : IProcessRunner
{
    public ProcessResult Run(string fileName, IReadOnlyList<string> arguments)
    {
        var startInfo = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using var process = System.Diagnostics.Process.Start(startInfo)!;
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return new ProcessResult(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr);
        }
        catch (Win32Exception ex)
        {
            throw new TrustStoreException($"could not run {fileName}: {ex.Message}");
        }
    }

    public bool CommandExists(string name)
    {
        string[] candidates = OperatingSystem.IsWindows() ? [name, name + ".exe"] : [name];
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        return path
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .SelectMany(dir => candidates.Select(candidate => Path.Combine(dir, candidate)))
            .Any(File.Exists);
    }
}
```

- [ ] **Step 5: Implement the NSS store**

`src/CertInstaller.Core/Stores/LinuxNssTrustStore.cs`:

```csharp
using CertInstaller.Core.Process;

namespace CertInstaller.Core.Stores;

public sealed class LinuxNssTrustStore(IProcessRunner runner, string homeDirectory) : ITrustStore
{
    private const string Tool = "certutil";

    private readonly string _databaseDirectory = Path.Combine(homeDirectory, ".pki", "nssdb");

    public string Description => $"Chrome/Chromium NSS database ({_databaseDirectory})";

    private string Database => "sql:" + _databaseDirectory;

    private bool DatabaseExists => File.Exists(Path.Combine(_databaseDirectory, "cert9.db"));

    public void Install(CertificateFile cert)
    {
        EnsureTool();
        EnsureDatabase();
        var trust = cert.IsCertificateAuthority ? "C,," : "P,,";
        runner.Run(Tool, ["-d", Database, "-A", "-t", trust, "-n", cert.Nickname, "-i", cert.Path])
            .EnsureSuccess("add certificate to the NSS database");
    }

    public void Uninstall(CertificateFile cert)
    {
        EnsureTool();
        runner.Run(Tool, ["-d", Database, "-D", "-n", cert.Nickname])
            .EnsureSuccess("remove certificate from the NSS database");
    }

    public bool IsTrusted(CertificateFile cert)
    {
        EnsureTool();
        if (!DatabaseExists)
        {
            return false;
        }

        return runner.Run(Tool, ["-d", Database, "-L", "-n", cert.Nickname]).ExitCode == 0;
    }

    private void EnsureDatabase()
    {
        if (DatabaseExists)
        {
            return;
        }

        Directory.CreateDirectory(_databaseDirectory);
        runner.Run(Tool, ["-d", Database, "-N", "--empty-password"]).EnsureSuccess("create the NSS database");
    }

    private void EnsureTool()
    {
        if (!runner.CommandExists(Tool))
        {
            throw new TrustStoreException(
                "NSS certutil not found",
                "install libnss3-tools (Debian/Ubuntu), nss-tools (Fedora) or nss (Arch)");
        }
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `dotnet test`
Expected: `Passed!  - Failed: 0, Passed: 34`

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: add trust store abstraction, process runner and Linux NSS store"
```

---

### Task 4: Linux system trust store

**Files:**
- Create: `src/CertInstaller.Core/Stores/LinuxSystemTrustStore.cs`
- Test: `tests/CertInstaller.Tests/LinuxSystemTrustStoreTests.cs`

**Interfaces:**
- Consumes: `ITrustStore`, `TrustStoreException`, `IProcessRunner`, `ProcessResult.EnsureSuccess`, `CertificateFile` (`Nickname`, `ToPem()`), `FakeProcessRunner`, `TestCertificates`, `TempDirectory`.
- Produces: `public sealed class LinuxSystemTrustStore(IProcessRunner runner, bool isPrivileged, string debianAnchorDirectory = "/usr/local/share/ca-certificates", string redHatAnchorDirectory = "/etc/pki/ca-trust/source/anchors") : ITrustStore`.

- [ ] **Step 1: Write the failing tests**

`tests/CertInstaller.Tests/LinuxSystemTrustStoreTests.cs`:

```csharp
using CertInstaller.Core;
using CertInstaller.Core.Stores;

namespace CertInstaller.Tests;

public sealed class LinuxSystemTrustStoreTests : IDisposable
{
    private readonly TempDirectory _root = new();
    private readonly TempDirectory _certs = new();
    private readonly FakeProcessRunner _runner = new();

    public void Dispose()
    {
        _root.Dispose();
        _certs.Dispose();
    }

    private string DebianDir => Path.Combine(_root.Path, "ca-certificates");

    private string RedHatDir => Path.Combine(_root.Path, "anchors");

    private LinuxSystemTrustStore Store(bool privileged = true) => new(_runner, privileged, DebianDir, RedHatDir);

    private CertificateFile Leaf() => TestCertificates.SelfSignedLeaf().ToFile(_certs);

    [Fact]
    public void Install_on_debian_writes_crt_and_refreshes()
    {
        _runner.AvailableCommands.Add("update-ca-certificates");
        var file = Leaf();

        Store().Install(file);

        Assert.Equal(file.ToPem(), File.ReadAllText(Path.Combine(DebianDir, file.Nickname + ".crt")));
        Assert.Equal(new[] { "update-ca-certificates" }, _runner.Calls);
    }

    [Fact]
    public void Install_on_redhat_writes_pem_and_extracts()
    {
        _runner.AvailableCommands.Add("update-ca-trust");
        var file = Leaf();

        Store().Install(file);

        Assert.Equal(file.ToPem(), File.ReadAllText(Path.Combine(RedHatDir, file.Nickname + ".pem")));
        Assert.Equal(new[] { "update-ca-trust extract" }, _runner.Calls);
    }

    [Fact]
    public void Install_requires_root()
    {
        _runner.AvailableCommands.Add("update-ca-certificates");

        var ex = Assert.Throws<TrustStoreException>(() => Store(privileged: false).Install(Leaf()));

        Assert.Contains("sudo", ex.Hint);
        Assert.Empty(_runner.Calls);
        Assert.False(Directory.Exists(DebianDir));
    }

    [Fact]
    public void Install_fails_without_supported_tool()
    {
        var ex = Assert.Throws<TrustStoreException>(() => Store().Install(Leaf()));

        Assert.Contains("update-ca-certificates", ex.Message);
    }

    [Fact]
    public void Install_reports_refresh_failure()
    {
        _runner.AvailableCommands.Add("update-ca-certificates");
        _runner.Respond("update-ca-certificates", 1, stderr: "boom");

        var ex = Assert.Throws<TrustStoreException>(() => Store().Install(Leaf()));

        Assert.Contains("boom", ex.Message);
    }

    [Fact]
    public void Uninstall_removes_anchor_and_refreshes()
    {
        _runner.AvailableCommands.Add("update-ca-certificates");
        var file = Leaf();
        Store().Install(file);
        _runner.Calls.Clear();

        Store().Uninstall(file);

        Assert.False(File.Exists(Path.Combine(DebianDir, file.Nickname + ".crt")));
        Assert.Equal(new[] { "update-ca-certificates" }, _runner.Calls);
    }

    [Fact]
    public void Uninstall_requires_root()
    {
        _runner.AvailableCommands.Add("update-ca-certificates");

        var ex = Assert.Throws<TrustStoreException>(() => Store(privileged: false).Uninstall(Leaf()));

        Assert.Contains("sudo", ex.Hint);
    }

    [Fact]
    public void IsTrusted_true_when_anchor_matches_even_without_root()
    {
        _runner.AvailableCommands.Add("update-ca-certificates");
        var file = Leaf();
        Store().Install(file);

        Assert.True(Store(privileged: false).IsTrusted(file));
    }

    [Fact]
    public void IsTrusted_false_when_anchor_missing()
    {
        _runner.AvailableCommands.Add("update-ca-certificates");

        Assert.False(Store().IsTrusted(Leaf()));
    }

    [Fact]
    public void IsTrusted_false_when_anchor_holds_different_certificate()
    {
        _runner.AvailableCommands.Add("update-ca-certificates");
        var file = Leaf();
        Directory.CreateDirectory(DebianDir);
        File.WriteAllText(
            Path.Combine(DebianDir, file.Nickname + ".crt"),
            TestCertificates.SelfSignedLeaf().ExportCertificatePem());

        Assert.False(Store().IsTrusted(file));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test --filter FullyQualifiedName~LinuxSystemTrustStoreTests`
Expected: build FAILS with `The type or namespace name 'LinuxSystemTrustStore' could not be found`.

- [ ] **Step 3: Implement**

`src/CertInstaller.Core/Stores/LinuxSystemTrustStore.cs`:

```csharp
using CertInstaller.Core.Process;

namespace CertInstaller.Core.Stores;

public sealed class LinuxSystemTrustStore(
    IProcessRunner runner,
    bool isPrivileged,
    string debianAnchorDirectory = "/usr/local/share/ca-certificates",
    string redHatAnchorDirectory = "/etc/pki/ca-trust/source/anchors") : ITrustStore
{
    public string Description => "Linux system trust store";

    public void Install(CertificateFile cert)
    {
        EnsurePrivileged();
        var distro = Detect();
        var anchor = distro.AnchorPath(cert);
        Directory.CreateDirectory(distro.AnchorDirectory);
        File.WriteAllText(anchor, cert.ToPem());
        Refresh(distro);
    }

    public void Uninstall(CertificateFile cert)
    {
        EnsurePrivileged();
        var distro = Detect();
        File.Delete(distro.AnchorPath(cert));
        Refresh(distro);
    }

    public bool IsTrusted(CertificateFile cert)
    {
        var anchor = Detect().AnchorPath(cert);
        return File.Exists(anchor) && File.ReadAllText(anchor).Trim() == cert.ToPem().Trim();
    }

    private Distro Detect()
    {
        if (runner.CommandExists("update-ca-certificates"))
        {
            return new Distro(debianAnchorDirectory, ".crt", "update-ca-certificates", []);
        }

        if (runner.CommandExists("update-ca-trust"))
        {
            return new Distro(redHatAnchorDirectory, ".pem", "update-ca-trust", ["extract"]);
        }

        throw new TrustStoreException(
            "no supported system trust tool found (update-ca-certificates or update-ca-trust)",
            "install your distribution's ca-certificates package");
    }

    private void Refresh(Distro distro) =>
        runner.Run(distro.RefreshCommand, distro.RefreshArguments).EnsureSuccess("refresh the system trust store");

    private void EnsurePrivileged()
    {
        if (!isPrivileged)
        {
            throw new TrustStoreException("changing the system trust store requires root", "re-run with sudo");
        }
    }

    private sealed record Distro(
        string AnchorDirectory,
        string Extension,
        string RefreshCommand,
        IReadOnlyList<string> RefreshArguments)
    {
        public string AnchorPath(CertificateFile cert) => Path.Combine(AnchorDirectory, cert.Nickname + Extension);
    }
}
```

(`File.Delete` does not throw when the file is missing.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test`
Expected: `Passed!  - Failed: 0, Passed: 44`

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add Linux system trust store (Debian and Fedora families)"
```

---

### Task 5: macOS keychain store

**Files:**
- Create: `src/CertInstaller.Core/Stores/MacKeychainTrustStore.cs`
- Test: `tests/CertInstaller.Tests/MacKeychainTrustStoreTests.cs`

**Interfaces:**
- Consumes: `ITrustStore`, `Scope`, `TrustStoreException`, `IProcessRunner`, `ProcessResult.EnsureSuccess`, `CertificateFile` (`Path`, `Sha1`, `IsSelfSigned`), `FakeProcessRunner`, `TestCertificates`, `TempDirectory`.
- Produces: `public sealed class MacKeychainTrustStore(Scope scope, IProcessRunner runner, string homeDirectory, bool isPrivileged) : ITrustStore`.

- [ ] **Step 1: Write the failing tests**

`tests/CertInstaller.Tests/MacKeychainTrustStoreTests.cs`:

```csharp
using CertInstaller.Core;
using CertInstaller.Core.Stores;

namespace CertInstaller.Tests;

public sealed class MacKeychainTrustStoreTests : IDisposable
{
    private const string Tool = "/usr/bin/security";
    private const string SystemKeychain = "/Library/Keychains/System.keychain";

    private readonly TempDirectory _home = new();
    private readonly TempDirectory _certs = new();
    private readonly FakeProcessRunner _runner = new();

    public void Dispose()
    {
        _home.Dispose();
        _certs.Dispose();
    }

    private string LoginKeychain => Path.Combine(_home.Path, "Library", "Keychains", "login.keychain-db");

    private MacKeychainTrustStore Store(Scope scope, bool privileged = false) =>
        new(scope, _runner, _home.Path, privileged);

    private CertificateFile Leaf() => TestCertificates.SelfSignedLeaf().ToFile(_certs);

    [Fact]
    public void Install_user_scope_trusts_in_login_keychain()
    {
        var file = Leaf();

        Store(Scope.User).Install(file);

        Assert.Equal(
            new[] { $"{Tool} add-trusted-cert -r trustRoot -k {LoginKeychain} {file.Path}" },
            _runner.Calls);
    }

    [Fact]
    public void Install_system_scope_uses_admin_domain()
    {
        var file = Leaf();

        Store(Scope.System, privileged: true).Install(file);

        Assert.Equal(
            new[] { $"{Tool} add-trusted-cert -d -r trustRoot -k {SystemKeychain} {file.Path}" },
            _runner.Calls);
    }

    [Fact]
    public void Install_system_scope_requires_root()
    {
        var ex = Assert.Throws<TrustStoreException>(() => Store(Scope.System).Install(Leaf()));

        Assert.Contains("sudo", ex.Hint);
        Assert.Empty(_runner.Calls);
    }

    [Fact]
    public void Install_ca_issued_leaf_uses_trust_as_root()
    {
        using var ca = TestCertificates.CertificateAuthority();
        var file = TestCertificates.LeafSignedBy(ca).ToFile(_certs);

        Store(Scope.User).Install(file);

        Assert.Contains("-r trustAsRoot", _runner.Calls.Single());
    }

    [Fact]
    public void Install_reports_failure()
    {
        _runner.Respond($"{Tool} add-trusted-cert", 1, stderr: "User interaction is not allowed.");

        var ex = Assert.Throws<TrustStoreException>(() => Store(Scope.User).Install(Leaf()));

        Assert.Contains("User interaction is not allowed.", ex.Message);
    }

    [Fact]
    public void Uninstall_removes_trust_then_deletes_certificate()
    {
        var file = Leaf();

        Store(Scope.User).Uninstall(file);

        Assert.Equal(
            new[]
            {
                $"{Tool} remove-trusted-cert {file.Path}",
                $"{Tool} delete-certificate -Z {file.Sha1} {LoginKeychain}",
            },
            _runner.Calls);
    }

    [Fact]
    public void Uninstall_system_scope_uses_admin_domain()
    {
        var file = Leaf();

        Store(Scope.System, privileged: true).Uninstall(file);

        Assert.Equal(
            new[]
            {
                $"{Tool} remove-trusted-cert -d {file.Path}",
                $"{Tool} delete-certificate -Z {file.Sha1} {SystemKeychain}",
            },
            _runner.Calls);
    }

    [Fact]
    public void IsTrusted_true_when_in_keychain_and_verified()
    {
        var file = Leaf();
        _runner.Respond($"{Tool} find-certificate", 0, stdout: $"SHA-256 hash: {file.Sha256}\nSHA-1 hash: {file.Sha1}\n");

        Assert.True(Store(Scope.User).IsTrusted(file));
        Assert.Equal(
            new[]
            {
                $"{Tool} find-certificate -a -Z {LoginKeychain}",
                $"{Tool} verify-cert -c {file.Path}",
            },
            _runner.Calls);
    }

    [Fact]
    public void IsTrusted_false_when_not_in_keychain()
    {
        _runner.Respond($"{Tool} find-certificate", 0, stdout: "SHA-1 hash: 0000\n");

        Assert.False(Store(Scope.User).IsTrusted(Leaf()));
        Assert.Single(_runner.Calls);
    }

    [Fact]
    public void IsTrusted_false_when_verification_fails()
    {
        var file = Leaf();
        _runner.Respond($"{Tool} find-certificate", 0, stdout: $"SHA-1 hash: {file.Sha1}\n");
        _runner.Respond($"{Tool} verify-cert", 1);

        Assert.False(Store(Scope.User).IsTrusted(file));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test --filter FullyQualifiedName~MacKeychainTrustStoreTests`
Expected: build FAILS with `The type or namespace name 'MacKeychainTrustStore' could not be found`.

- [ ] **Step 3: Implement**

`src/CertInstaller.Core/Stores/MacKeychainTrustStore.cs`:

```csharp
using CertInstaller.Core.Process;

namespace CertInstaller.Core.Stores;

public sealed class MacKeychainTrustStore(
    Scope scope,
    IProcessRunner runner,
    string homeDirectory,
    bool isPrivileged) : ITrustStore
{
    private const string Tool = "/usr/bin/security";

    public string Description => $"macOS keychain ({Keychain})";

    private bool IsSystem => scope == Scope.System;

    private string Keychain => IsSystem
        ? "/Library/Keychains/System.keychain"
        : Path.Combine(homeDirectory, "Library", "Keychains", "login.keychain-db");

    public void Install(CertificateFile cert)
    {
        EnsurePrivileged();
        var arguments = new List<string> { "add-trusted-cert" };
        if (IsSystem)
        {
            arguments.Add("-d");
        }

        arguments.AddRange(["-r", cert.IsSelfSigned ? "trustRoot" : "trustAsRoot", "-k", Keychain, cert.Path]);
        runner.Run(Tool, arguments).EnsureSuccess("add trusted certificate to the keychain");
    }

    public void Uninstall(CertificateFile cert)
    {
        EnsurePrivileged();
        var arguments = new List<string> { "remove-trusted-cert" };
        if (IsSystem)
        {
            arguments.Add("-d");
        }

        arguments.Add(cert.Path);
        runner.Run(Tool, arguments).EnsureSuccess("remove certificate trust settings");
        runner.Run(Tool, ["delete-certificate", "-Z", cert.Sha1, Keychain])
            .EnsureSuccess("delete certificate from the keychain");
    }

    public bool IsTrusted(CertificateFile cert)
    {
        var found = runner.Run(Tool, ["find-certificate", "-a", "-Z", Keychain]);
        if (found.ExitCode != 0 ||
            !found.StdOut.Contains("SHA-1 hash: " + cert.Sha1, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return runner.Run(Tool, ["verify-cert", "-c", cert.Path]).ExitCode == 0;
    }

    private void EnsurePrivileged()
    {
        if (IsSystem && !isPrivileged)
        {
            throw new TrustStoreException("changing the System keychain requires root", "re-run with sudo");
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test`
Expected: `Passed!  - Failed: 0, Passed: 54`

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add macOS keychain trust store"
```

---

### Task 6: Windows store and store factory

**Files:**
- Create: `src/CertInstaller.Core/Stores/WindowsTrustStore.cs`
- Create: `src/CertInstaller.Core/TrustStoreFactory.cs`
- Test: `tests/CertInstaller.Tests/TrustStoreFactoryTests.cs`

**Interfaces:**
- Consumes: all stores from Tasks 3–5, `ProcessRunner`, `Scope`, `TrustStoreException`.
- Produces:
  - `[SupportedOSPlatform("windows")] public sealed class WindowsTrustStore(Scope scope, bool isPrivileged) : ITrustStore`
  - `public static class TrustStoreFactory { public static ITrustStore Create(Scope scope); }` — matches `Func<Scope, ITrustStore>` used by `CliApp` in Task 7.

- [ ] **Step 1: Write the failing tests**

`tests/CertInstaller.Tests/TrustStoreFactoryTests.cs`:

```csharp
using CertInstaller.Core;
using CertInstaller.Core.Stores;

namespace CertInstaller.Tests;

public sealed class TrustStoreFactoryTests : IDisposable
{
    private readonly TempDirectory _certs = new();

    public void Dispose() => _certs.Dispose();

    [Fact]
    public void Creates_store_for_current_os()
    {
        var user = TrustStoreFactory.Create(Scope.User);
        var system = TrustStoreFactory.Create(Scope.System);

        if (OperatingSystem.IsWindows())
        {
            Assert.IsType<WindowsTrustStore>(user);
            Assert.IsType<WindowsTrustStore>(system);
        }
        else if (OperatingSystem.IsMacOS())
        {
            Assert.IsType<MacKeychainTrustStore>(user);
            Assert.IsType<MacKeychainTrustStore>(system);
        }
        else if (OperatingSystem.IsLinux())
        {
            Assert.IsType<LinuxNssTrustStore>(user);
            Assert.IsType<LinuxSystemTrustStore>(system);
        }
    }

    // Runs only on Windows CI: read-only / refused operations, never modifies a store.
    [Fact]
    public void Windows_system_scope_requires_administrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var file = TestCertificates.SelfSignedLeaf().ToFile(_certs);
        var ex = Assert.Throws<TrustStoreException>(
            () => new WindowsTrustStore(Scope.System, isPrivileged: false).Install(file));

        Assert.Contains("Administrator", ex.Hint);
    }

    [Fact]
    public void Windows_unknown_certificate_is_not_trusted()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var file = TestCertificates.SelfSignedLeaf().ToFile(_certs);

        Assert.False(new WindowsTrustStore(Scope.User, isPrivileged: false).IsTrusted(file));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test --filter FullyQualifiedName~TrustStoreFactoryTests`
Expected: build FAILS with `The type or namespace name 'WindowsTrustStore' could not be found`.

- [ ] **Step 3: Implement the Windows store**

`src/CertInstaller.Core/Stores/WindowsTrustStore.cs`:

```csharp
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertInstaller.Core.Stores;

[SupportedOSPlatform("windows")]
public sealed class WindowsTrustStore(Scope scope, bool isPrivileged) : ITrustStore
{
    private StoreLocation Location => scope == Scope.System ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;

    public string Description => $"Windows {Location} Root store";

    public void Install(CertificateFile cert)
    {
        EnsurePrivileged();
        using var store = Open(OpenFlags.ReadWrite);
        try
        {
            store.Add(cert.Certificate);
        }
        catch (CryptographicException ex)
        {
            throw new TrustStoreException($"could not add certificate: {ex.Message}", FailureHint);
        }
    }

    public void Uninstall(CertificateFile cert)
    {
        EnsurePrivileged();
        using var store = Open(OpenFlags.ReadWrite);
        try
        {
            store.RemoveRange(Find(store, cert));
        }
        catch (CryptographicException ex)
        {
            throw new TrustStoreException($"could not remove certificate: {ex.Message}", FailureHint);
        }
    }

    public bool IsTrusted(CertificateFile cert)
    {
        using var store = Open(OpenFlags.ReadOnly);
        return Find(store, cert).Count > 0;
    }

    private string FailureHint => scope == Scope.System
        ? "re-run from an elevated (Administrator) terminal"
        : "the Windows security confirmation may have been declined; run again and choose Yes";

    private static X509Certificate2Collection Find(X509Store store, CertificateFile cert) =>
        store.Certificates.Find(X509FindType.FindByThumbprint, cert.Sha1, validOnly: false);

    private X509Store Open(OpenFlags flags)
    {
        var store = new X509Store(StoreName.Root, Location);
        try
        {
            store.Open(flags);
            return store;
        }
        catch (CryptographicException ex)
        {
            store.Dispose();
            throw new TrustStoreException($"could not open {Description}: {ex.Message}", FailureHint);
        }
    }

    private void EnsurePrivileged()
    {
        if (scope == Scope.System && !isPrivileged)
        {
            throw new TrustStoreException(
                "changing the LocalMachine Root store requires Administrator rights",
                "re-run from an elevated (Administrator) terminal");
        }
    }
}
```

- [ ] **Step 4: Implement the factory**

`src/CertInstaller.Core/TrustStoreFactory.cs`:

```csharp
using System.Runtime.InteropServices;
using CertInstaller.Core.Process;
using CertInstaller.Core.Stores;

namespace CertInstaller.Core;

public static class TrustStoreFactory
{
    public static ITrustStore Create(Scope scope)
    {
        var runner = new ProcessRunner();
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var privileged = Environment.IsPrivilegedProcess;

        if (OperatingSystem.IsWindows())
        {
            return new WindowsTrustStore(scope, privileged);
        }

        if (OperatingSystem.IsMacOS())
        {
            return new MacKeychainTrustStore(scope, runner, home, privileged);
        }

        if (OperatingSystem.IsLinux())
        {
            return scope == Scope.System
                ? new LinuxSystemTrustStore(runner, privileged)
                : new LinuxNssTrustStore(runner, home);
        }

        throw new TrustStoreException($"unsupported operating system: {RuntimeInformation.OSDescription}");
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test`
Expected: `Passed!  - Failed: 0, Passed: 57` (the two Windows-only tests pass trivially on Linux/macOS).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: add Windows Root store and OS-based store factory"
```

---

### Task 7: CLI application

**Files:**
- Create: `src/CertInstaller.Cli/CliEnvironment.cs`, `src/CertInstaller.Cli/CliApp.cs`
- Modify: `src/CertInstaller.Cli/Program.cs` (replace template content)
- Create: `tests/CertInstaller.Tests/Support/FakeTrustStore.cs`
- Test: `tests/CertInstaller.Tests/CliAppTests.cs`

**Interfaces:**
- Consumes: `CertificateFile` (`Load`, `IsSelfSigned`, `IsCertificateAuthority`, `Issuer`, `Nickname`, `Path`, `GetWarnings`), `CertificateLoadException`, `ITrustStore`, `Scope`, `TrustStoreException` (`Hint`), `TrustStoreFactory.Create`.
- Produces:
  - `namespace CertInstaller.Cli`: `public sealed record CliEnvironment(bool IsLinux, bool IsInteractive, bool IsPrivileged, DateTimeOffset Now)`.
  - `public sealed class CliApp(TextWriter stdout, TextWriter stderr, TextReader stdin, CliEnvironment environment, Func<Scope, ITrustStore> createStore)` with `int Run(string[] args)` and constants `Ok = 0`, `NotTrusted = 1`, `UsageError = 2`, `StoreError = 3`.

- [ ] **Step 1: Write the fake store**

`tests/CertInstaller.Tests/Support/FakeTrustStore.cs`:

```csharp
using CertInstaller.Core;

namespace CertInstaller.Tests;

internal sealed class FakeTrustStore(string description) : ITrustStore
{
    public HashSet<string> Trusted { get; } = new();

    public List<string> Calls { get; } = new();

    public Exception? FailWith { get; set; }

    public string Description => description;

    public void Install(CertificateFile cert)
    {
        Calls.Add("install");
        ThrowIfFailing();
        Trusted.Add(cert.Sha256);
    }

    public void Uninstall(CertificateFile cert)
    {
        Calls.Add("uninstall");
        ThrowIfFailing();
        Trusted.Remove(cert.Sha256);
    }

    public bool IsTrusted(CertificateFile cert)
    {
        ThrowIfFailing();
        return Trusted.Contains(cert.Sha256);
    }

    private void ThrowIfFailing()
    {
        if (FailWith is not null)
        {
            throw FailWith;
        }
    }
}
```

- [ ] **Step 2: Write the failing tests**

`tests/CertInstaller.Tests/CliAppTests.cs`:

```csharp
using CertInstaller.Cli;
using CertInstaller.Core;

namespace CertInstaller.Tests;

public sealed class CliAppTests : IDisposable
{
    private readonly TempDirectory _dir = new();
    private readonly StringWriter _out = new();
    private readonly StringWriter _err = new();
    private readonly FakeTrustStore _user = new("user store");
    private readonly FakeTrustStore _system = new("system store");

    public void Dispose() => _dir.Dispose();

    private int Run(string[] args, string stdin = "", bool isLinux = false, bool interactive = false, bool privileged = false)
    {
        var environment = new CliEnvironment(isLinux, interactive, privileged, DateTimeOffset.UtcNow);
        return new CliApp(_out, _err, new StringReader(stdin), environment, s => s == Scope.System ? _system : _user)
            .Run(args);
    }

    private string LeafPath(string name = "leaf.pem") =>
        _dir.Write(name, TestCertificates.SelfSignedLeaf().ExportCertificatePem());

    private string Sha256(string path) => CertificateFile.Load(path).Sha256;

    [Fact]
    public void Help_prints_usage()
    {
        Assert.Equal(CliApp.Ok, Run(["--help"]));
        Assert.Contains("certinstall install", _out.ToString());
    }

    [Theory]
    [InlineData(new string[0], "missing command")]
    [InlineData(new[] { "frobnicate", "x.pem" }, "unknown command 'frobnicate'")]
    [InlineData(new[] { "install" }, "missing certificate file")]
    [InlineData(new[] { "install", "a.pem", "b.pem" }, "only one certificate file")]
    [InlineData(new[] { "uninstall", "a.pem", "--force" }, "unknown option '--force'")]
    [InlineData(new[] { "status", "a.pem", "--verbose" }, "unknown option '--verbose'")]
    public void Usage_errors_exit_2(string[] args, string message)
    {
        Assert.Equal(CliApp.UsageError, Run(args));
        Assert.Contains($"error: {message}", _err.ToString());
        Assert.Contains("usage:", _err.ToString());
    }

    [Fact]
    public void Missing_file_exits_2()
    {
        Assert.Equal(CliApp.UsageError, Run(["install", Path.Combine(_dir.Path, "nope.pem")]));
        Assert.Contains("error: file not found", _err.ToString());
    }

    [Fact]
    public void Install_adds_to_user_store()
    {
        var path = LeafPath();

        Assert.Equal(CliApp.Ok, Run(["install", path]));

        Assert.Contains(Sha256(path), _user.Trusted);
        Assert.Empty(_system.Calls);
        Assert.Contains("installed certinstall-", _out.ToString());
        Assert.Contains("user store", _out.ToString());
    }

    [Fact]
    public void System_flag_before_file_targets_system_store()
    {
        var path = LeafPath();

        Assert.Equal(CliApp.Ok, Run(["install", "--system", path]));

        Assert.Contains(Sha256(path), _system.Trusted);
        Assert.Empty(_user.Calls);
    }

    [Fact]
    public void Install_is_idempotent()
    {
        var path = LeafPath();
        Run(["install", path]);

        Assert.Equal(CliApp.Ok, Run(["install", path]));

        Assert.Single(_user.Calls);
        Assert.Contains("already trusted", _out.ToString());
    }

    [Fact]
    public void Install_prints_runtime_guidance()
    {
        var path = LeafPath();

        Run(["install", path]);

        Assert.Contains($"NODE_EXTRA_CA_CERTS={path}", _out.ToString());
        Assert.Contains("--use-system-ca", _out.ToString());
        Assert.Contains($"REQUESTS_CA_BUNDLE={path}", _out.ToString());
    }

    [Fact]
    public void Install_refuses_ca_issued_leaf()
    {
        using var ca = TestCertificates.CertificateAuthority();
        var path = _dir.Write("issued.pem", TestCertificates.LeafSignedBy(ca).ExportCertificatePem());

        Assert.Equal(CliApp.UsageError, Run(["install", path]));

        Assert.Contains("install the issuing CA instead", _err.ToString());
        Assert.Empty(_user.Calls);
    }

    [Fact]
    public void Install_ca_issued_leaf_with_force()
    {
        using var ca = TestCertificates.CertificateAuthority();
        var path = _dir.Write("issued.pem", TestCertificates.LeafSignedBy(ca).ExportCertificatePem());

        Assert.Equal(CliApp.Ok, Run(["install", path, "--force"]));

        Assert.Contains(Sha256(path), _user.Trusted);
    }

    [Fact]
    public void Install_accepts_ca()
    {
        var path = _dir.Write("ca.pem", TestCertificates.CertificateAuthority().ExportCertificatePem());

        Assert.Equal(CliApp.Ok, Run(["install", path]));
    }

    [Fact]
    public void Install_warns_but_continues_for_leaf_without_san()
    {
        var path = _dir.Write("nosan.pem", TestCertificates.SelfSignedLeaf(dnsNames: []).ExportCertificatePem());

        Assert.Equal(CliApp.Ok, Run(["install", path]));

        Assert.Contains("warning: certificate has no Subject Alternative Name", _err.ToString());
        Assert.Contains(Sha256(path), _user.Trusted);
    }

    [Fact]
    public void Store_failure_exits_3_with_hint()
    {
        _user.FailWith = new TrustStoreException("boom", "do something");

        Assert.Equal(CliApp.StoreError, Run(["install", LeafPath()]));

        Assert.Contains("error: boom", _err.ToString());
        Assert.Contains("hint: do something", _err.ToString());
    }

    [Fact]
    public void Status_reports_trusted_and_not_trusted()
    {
        var path = LeafPath();

        Assert.Equal(CliApp.NotTrusted, Run(["status", path]));
        Assert.Contains("not trusted", _out.ToString());

        _user.Trusted.Add(Sha256(path));
        Assert.Equal(CliApp.Ok, Run(["status", path]));
    }

    [Fact]
    public void Uninstall_when_not_installed_is_ok()
    {
        Assert.Equal(CliApp.Ok, Run(["uninstall", LeafPath()]));

        Assert.Empty(_user.Calls);
        Assert.Contains("not installed", _out.ToString());
    }

    [Fact]
    public void Uninstall_removes_installed_certificate()
    {
        var path = LeafPath();
        _user.Trusted.Add(Sha256(path));

        Assert.Equal(CliApp.Ok, Run(["uninstall", path]));

        Assert.Empty(_user.Trusted);
        Assert.Contains("removed certinstall-", _out.ToString());
    }

    [Fact]
    public void Linux_non_interactive_prints_system_hint()
    {
        var path = LeafPath();

        Assert.Equal(CliApp.Ok, Run(["install", path], isLinux: true));

        Assert.Contains($"hint: to also trust it system-wide (curl/Go/OpenSSL), run: sudo certinstall install --system {path}", _err.ToString());
        Assert.Contains("Restart Chrome", _out.ToString());
        Assert.Empty(_system.Calls);
    }

    [Fact]
    public void Linux_interactive_yes_without_root_prints_command()
    {
        var path = LeafPath();

        Assert.Equal(CliApp.Ok, Run(["install", path], stdin: "y\n", isLinux: true, interactive: true));

        Assert.Contains("Also trust system-wide", _out.ToString());
        Assert.Contains($"run: sudo certinstall install --system {path}", _out.ToString());
        Assert.Empty(_system.Calls);
    }

    [Fact]
    public void Linux_interactive_yes_as_root_installs_system_wide()
    {
        var path = LeafPath();

        Assert.Equal(CliApp.Ok, Run(["install", path], stdin: "yes\n", isLinux: true, interactive: true, privileged: true));

        Assert.Contains(Sha256(path), _system.Trusted);
    }

    [Theory]
    [InlineData("")]
    [InlineData("\n")]
    [InlineData("n\n")]
    public void Linux_interactive_blank_answer_does_nothing(string answer)
    {
        Assert.Equal(CliApp.Ok, Run(["install", LeafPath()], stdin: answer, isLinux: true, interactive: true));

        Assert.DoesNotContain("run: sudo", _out.ToString());
        Assert.Empty(_system.Calls);
    }

    [Fact]
    public void Non_linux_never_prompts()
    {
        Run(["install", LeafPath()], stdin: "y\n", interactive: true);

        Assert.DoesNotContain("Also trust system-wide", _out.ToString());
        Assert.DoesNotContain("sudo", _err.ToString());
    }

    [Fact]
    public void Hint_quotes_path_with_spaces()
    {
        var path = LeafPath("my cert.pem");

        Run(["install", path], isLinux: true);

        Assert.Contains($"--system \"{path}\"", _err.ToString());
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `dotnet test --filter FullyQualifiedName~CliAppTests`
Expected: build FAILS with `The type or namespace name 'CliEnvironment' could not be found`.

- [ ] **Step 4: Implement**

`src/CertInstaller.Cli/CliEnvironment.cs`:

```csharp
namespace CertInstaller.Cli;

public sealed record CliEnvironment(bool IsLinux, bool IsInteractive, bool IsPrivileged, DateTimeOffset Now);
```

`src/CertInstaller.Cli/CliApp.cs`:

```csharp
using System.Diagnostics.CodeAnalysis;
using CertInstaller.Core;

namespace CertInstaller.Cli;

public sealed class CliApp(
    TextWriter stdout,
    TextWriter stderr,
    TextReader stdin,
    CliEnvironment environment,
    Func<Scope, ITrustStore> createStore)
{
    public const int Ok = 0;
    public const int NotTrusted = 1;
    public const int UsageError = 2;
    public const int StoreError = 3;

    private const string Usage = """
        usage:
          certinstall install   <cert-file> [--system] [--force]
          certinstall uninstall <cert-file> [--system]
          certinstall status    <cert-file> [--system]
        """;

    public int Run(string[] args)
    {
        if (args.Length == 1 && args[0] is "-h" or "--help")
        {
            stdout.WriteLine(Usage);
            return Ok;
        }

        if (!TryParse(args, out var command, out var error))
        {
            stderr.WriteLine($"error: {error}");
            stderr.WriteLine(Usage);
            return UsageError;
        }

        CertificateFile cert;
        try
        {
            cert = CertificateFile.Load(command.File);
        }
        catch (CertificateLoadException ex)
        {
            stderr.WriteLine($"error: {ex.Message}");
            return UsageError;
        }

        try
        {
            return command.Name switch
            {
                "install" => Install(cert, command),
                "uninstall" => Uninstall(cert, command.Scope),
                _ => Status(cert, command.Scope),
            };
        }
        catch (TrustStoreException ex)
        {
            stderr.WriteLine($"error: {ex.Message}");
            if (ex.Hint is not null)
            {
                stderr.WriteLine($"hint: {ex.Hint}");
            }

            return StoreError;
        }
    }

    private int Install(CertificateFile cert, Command command)
    {
        if (!cert.IsSelfSigned && !cert.IsCertificateAuthority && !command.Force)
        {
            stderr.WriteLine(
                $"error: this certificate is issued by {cert.Issuer}; install the issuing CA instead (or pass --force)");
            return UsageError;
        }

        foreach (var warning in cert.GetWarnings(environment.Now))
        {
            stderr.WriteLine($"warning: {warning}");
        }

        InstallInto(createStore(command.Scope), cert);
        PrintGuidance(cert, command.Scope);
        if (environment.IsLinux && command.Scope == Scope.User)
        {
            OfferSystemInstall(cert);
        }

        return Ok;
    }

    private void InstallInto(ITrustStore store, CertificateFile cert)
    {
        if (store.IsTrusted(cert))
        {
            stdout.WriteLine($"already trusted: {cert.Nickname} in {store.Description}");
            return;
        }

        store.Install(cert);
        stdout.WriteLine($"installed {cert.Nickname} into {store.Description}");
    }

    private int Uninstall(CertificateFile cert, Scope scope)
    {
        var store = createStore(scope);
        if (!store.IsTrusted(cert))
        {
            stdout.WriteLine($"not installed: {cert.Nickname} in {store.Description}");
            return Ok;
        }

        store.Uninstall(cert);
        stdout.WriteLine($"removed {cert.Nickname} from {store.Description}");
        return Ok;
    }

    private int Status(CertificateFile cert, Scope scope)
    {
        var store = createStore(scope);
        var trusted = store.IsTrusted(cert);
        stdout.WriteLine($"{(trusted ? "trusted" : "not trusted")} ({store.Description})");
        return trusted ? Ok : NotTrusted;
    }

    private void PrintGuidance(CertificateFile cert, Scope scope)
    {
        var path = Quote(cert.Path);
        stdout.WriteLine();
        stdout.WriteLine("Runtimes that ignore the OS trust store:");
        stdout.WriteLine($"  Node.js:         NODE_EXTRA_CA_CERTS={path}  (or run node with --use-system-ca)");
        stdout.WriteLine($"  Python requests: REQUESTS_CA_BUNDLE={path}  (replaces the default CA bundle)");
        if (environment.IsLinux && scope == Scope.User)
        {
            stdout.WriteLine("Restart Chrome/Chromium for the change to take effect.");
        }
    }

    private void OfferSystemInstall(CertificateFile cert)
    {
        var command = $"sudo certinstall install --system {Quote(cert.Path)}";
        if (!environment.IsInteractive)
        {
            stderr.WriteLine($"hint: to also trust it system-wide (curl/Go/OpenSSL), run: {command}");
            return;
        }

        stdout.Write("Also trust system-wide for curl/Go/OpenSSL? [y/N] ");
        var answer = stdin.ReadLine()?.Trim();
        if (!string.Equals(answer, "y", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(answer, "yes", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (!environment.IsPrivileged)
        {
            stdout.WriteLine($"run: {command}");
            return;
        }

        InstallInto(createStore(Scope.System), cert);
    }

    private static string Quote(string path) => path.Contains(' ') ? $"\"{path}\"" : path;

    private static bool TryParse(
        string[] args,
        [NotNullWhen(true)] out Command? command,
        [NotNullWhen(false)] out string? error)
    {
        command = null;
        error = null;
        if (args.Length == 0)
        {
            error = "missing command";
            return false;
        }

        var name = args[0];
        if (name is not ("install" or "uninstall" or "status"))
        {
            error = $"unknown command '{name}'";
            return false;
        }

        string? file = null;
        var system = false;
        var force = false;
        foreach (var arg in args.Skip(1))
        {
            if (arg == "--system")
            {
                system = true;
            }
            else if (arg == "--force" && name == "install")
            {
                force = true;
            }
            else if (arg.StartsWith('-'))
            {
                error = $"unknown option '{arg}'";
                return false;
            }
            else if (file is not null)
            {
                error = "only one certificate file may be given";
                return false;
            }
            else
            {
                file = arg;
            }
        }

        if (file is null)
        {
            error = "missing certificate file";
            return false;
        }

        command = new Command(name, file, system ? Scope.System : Scope.User, force);
        return true;
    }

    private sealed record Command(string Name, string File, Scope Scope, bool Force);
}
```

Note `args[0] is "-h" or "--help"` binds as `args[0] is ("-h" or "--help")` — pattern combinators bind tighter than `&&`, so the condition is correct.

Replace `src/CertInstaller.Cli/Program.cs` entirely with:

```csharp
using CertInstaller.Cli;
using CertInstaller.Core;

var environment = new CliEnvironment(
    IsLinux: OperatingSystem.IsLinux(),
    IsInteractive: !Console.IsInputRedirected && !Console.IsOutputRedirected,
    IsPrivileged: Environment.IsPrivilegedProcess,
    Now: DateTimeOffset.UtcNow);

try
{
    return new CliApp(Console.Out, Console.Error, Console.In, environment, TrustStoreFactory.Create).Run(args);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"error: unexpected failure: {ex.Message}");
    if (Environment.GetEnvironmentVariable("CERTINSTALL_DEBUG") == "1")
    {
        Console.Error.WriteLine(ex);
    }

    return CliApp.StoreError;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test`
Expected: `Passed!  - Failed: 0, Passed: 85` (57 earlier + 28 CLI cases including theory rows).

- [ ] **Step 6: Smoke-test the real binary on Linux (read-only commands)**

```bash
dotnet run --project src/CertInstaller.Cli -- --help; echo "exit=$?"
dotnet run --project src/CertInstaller.Cli -- status /nonexistent.pem; echo "exit=$?"
```

Expected: usage text with `exit=0`; then `error: file not found: /nonexistent.pem` with `exit=2`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: add certinstall CLI with install, uninstall and status"
```

---

### Task 8: Publishing, CI, release workflow and docs

**Files:**
- Create: `scripts/publish.sh`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`
- Create: `README.md`, `docs/manual-test-checklist.md`
- Modify: `AGENTS.md` (Commands section and first rule)

**Interfaces:**
- Consumes: the `certinstall` executable from Task 7.
- Produces: `scripts/publish.sh <version> [rid...]` writing `dist/certinstall-<version>-<rid>.zip` (Windows) or `.tar.gz` (others).

- [ ] **Step 1: Write the publish script**

`scripts/publish.sh`:

```bash
#!/usr/bin/env bash
# Usage: scripts/publish.sh <version> [rid...]
# Builds self-contained single-file binaries into dist/ and packages each RID.
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:?usage: scripts/publish.sh <version> [rid...]}"
shift
rids=("$@")
if [[ ${#rids[@]} -eq 0 ]]; then
  rids=(win-x64 osx-arm64 osx-x64 linux-x64 linux-arm64)
fi

mkdir -p dist
for rid in "${rids[@]}"; do
  out="dist/$rid"
  rm -rf "$out"
  dotnet publish src/CertInstaller.Cli -c Release -r "$rid" --self-contained \
    -p:PublishSingleFile=true -p:PublishTrimmed=true -p:DebugType=none -o "$out"
  name="certinstall-$version-$rid"
  if [[ $rid == win-* ]]; then
    (cd "$out" && zip -q "../$name.zip" certinstall.exe)
  else
    tar -czf "dist/$name.tar.gz" -C "$out" certinstall
  fi
  echo "packaged dist/$name"
done
```

Run:

```bash
chmod +x scripts/publish.sh
./scripts/publish.sh dev linux-x64 win-x64
ls dist
./dist/linux-x64/certinstall --help; echo "exit=$?"
```

Expected: publish finishes with **no trim warnings** (they would fail the build because warnings are errors); `dist` contains `certinstall-dev-linux-x64.tar.gz` and `certinstall-dev-win-x64.zip`; `--help` prints usage and `exit=0`. Add `dist/` to `.gitignore`:

```bash
printf '\n# publish output\ndist/\n' >> .gitignore
```

- [ ] **Step 2: CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          global-json-file: global.json
      - run: dotnet test
```

- [ ] **Step 3: Release workflow**

macOS binaries must be built on a macOS runner: the SDK only ad-hoc signs the apphost when publishing on macOS, and unsigned arm64 binaries are killed at launch.

`.github/workflows/release.yml`:

```yaml
name: release

on:
  push:
    tags: ['v*']

permissions:
  contents: write

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            rids: win-x64 linux-x64 linux-arm64
          - os: macos-latest
            rids: osx-arm64 osx-x64
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          global-json-file: global.json
      - run: dotnet test
      - run: ./scripts/publish.sh "${{ github.ref_name }}" ${{ matrix.rids }}
      - uses: actions/upload-artifact@v4
        with:
          name: dist-${{ matrix.os }}
          path: |
            dist/*.zip
            dist/*.tar.gz

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          path: dist
          merge-multiple: true
      - run: cd dist && sha256sum * > SHA256SUMS
      - run: gh release create "${{ github.ref_name }}" dist/* --repo "${{ github.repository }}" --generate-notes
        env:
          GH_TOKEN: ${{ github.token }}
```

- [ ] **Step 4: Manual test checklist**

`docs/manual-test-checklist.md`:

````markdown
# Manual test checklist

Run before every release on a real Windows PC, Mac and Linux desktop with Chrome
installed. Record the OS version and result for each step.

## Prepare a test certificate and server

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout key.pem -out cert.pem -days 30 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
openssl s_server -accept 8443 -cert cert.pem -key key.pem -www
```

(Windows: run these in Git Bash.) `wss://` uses the same TLS handshake as
`https://`, so loading `https://localhost:8443` in Chrome is the check.

## User scope

1. `certinstall status cert.pem` → `not trusted`, exit 1.
2. Open `https://localhost:8443` in Chrome → certificate warning.
3. `certinstall install cert.pem` → `installed certinstall-…`, exit 0.
   - Windows: a security confirmation dialog appears; choose Yes.
   - macOS: a password prompt appears.
   - Linux: answer `N` to the system-wide prompt.
4. `certinstall install cert.pem` again → `already trusted`, exit 0.
5. `certinstall status cert.pem` → `trusted`, exit 0.
6. Restart Chrome, reload the page → no warning.
7. `certinstall uninstall cert.pem` → `removed …`, exit 0.
8. `certinstall status cert.pem` → `not trusted`; restart Chrome → warning is back.

## System scope

1. Without elevation: `certinstall install --system cert.pem` → exit 3 with a
   `hint:` about sudo / Administrator.
2. Elevated (`sudo` or an Administrator terminal): repeat user-scope steps 3–8
   with `--system`.
3. Linux/macOS: while installed, `curl https://localhost:8443` succeeds without `-k`.

## Error handling

1. `certinstall install key.pem` → `no CERTIFICATE block`, exit 2.
2. Linux without `certutil` on PATH → exit 3 with a hint naming `libnss3-tools`.

## Open question to resolve on macOS

Confirm `status` reports `trusted` after install and `not trusted` after
uninstall. If not, record the output of `security find-certificate -a -Z <keychain>`
and `security verify-cert -c cert.pem` and update `MacKeychainTrustStore.IsTrusted`.
````

- [ ] **Step 5: README**

`README.md`:

````markdown
# certinstall

Trust a self-signed (or dev CA) certificate so local `https://` and `wss://`
endpoints load in Chrome/Edge without warnings.

```
certinstall install   <cert-file> [--system] [--force]
certinstall uninstall <cert-file> [--system]
certinstall status    <cert-file> [--system]
```

| OS | Default (user) | `--system` (needs sudo / Administrator) |
|----|----------------|------------------------------------------|
| Windows | CurrentUser Root store | LocalMachine Root store |
| macOS | login keychain | System keychain |
| Linux | Chrome/Chromium NSS db (`~/.pki/nssdb`, needs `certutil` from `libnss3-tools`) | distro CA store (`update-ca-certificates` / `update-ca-trust`) |

Exit codes: `0` ok / trusted, `1` not trusted, `2` usage or input error, `3` store error.

Node.js and Python ignore the OS store by default; `install` prints the
`NODE_EXTRA_CA_CERTS` / `REQUESTS_CA_BUNDLE` settings to use.

## Install

Download the archive for your platform from GitHub Releases and check it against `SHA256SUMS`.
Binaries are not code-signed yet:

- Windows: SmartScreen → "More info" → "Run anyway".
- macOS: `xattr -d com.apple.quarantine certinstall`.

## Build

```bash
dotnet test
./scripts/publish.sh dev linux-x64   # -> dist/
```

macOS binaries must be published on a Mac (or ad-hoc signed with `codesign --sign - certinstall`).
````

- [ ] **Step 6: Update AGENTS.md**

In `AGENTS.md`, replace the Commands block with:

````markdown
```bash
dotnet build
dotnet test                                        # unit tests (never touch real stores)
./scripts/publish.sh dev linux-x64                 # self-contained binary -> dist/
```

Real trust-store behaviour is verified manually with `docs/manual-test-checklist.md`.
````

and replace the first rule with:

```markdown
- Unit tests must never modify a real trust store. Use a fake `IProcessRunner`
  and assert on the exact command line. Real-store checks are manual
  (`docs/manual-test-checklist.md`).
```

- [ ] **Step 7: Verify and commit**

Run: `dotnet test && git status --short`
Expected: all tests pass; `dist/` does not appear in `git status`.

```bash
git add -A
git commit -m "build: add publish script, CI and release workflows, README and manual checklist"
```
