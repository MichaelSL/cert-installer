using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
