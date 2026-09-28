using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertInstaller.Core;

public sealed class CertificateFile : IDisposable
{
    private CertificateFile(string path, X509Certificate2 certificate)
    {
        Path = path;
        Certificate = certificate;
        Sha256 = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        Sha1 = certificate.Thumbprint;
        Nickname = "certinstall-" + Sha256[..16].ToLowerInvariant();
    }

    public string Path { get; }

    public string Sha256 { get; }

    public string Sha1 { get; }

    public string Nickname { get; }

    public string Subject => Certificate.Subject;

    public string Issuer => Certificate.Issuer;

    // Only trust-store backends (same assembly) need the raw certificate.
    internal X509Certificate2 Certificate { get; }

    public string ToPem() => Certificate.ExportCertificatePem();

    public void Dispose() => Certificate.Dispose();

    public static CertificateFile Load(string path)
    {
        var fullPath = System.IO.Path.GetFullPath(path);
        var bytes = ReadAllBytes(fullPath);

        // ImportFromPem finds nothing when the text starts with U+FEFF, which would let a
        // BOM-prefixed multi-certificate file fall through to the DER/first-cert path below.
        var text = Encoding.UTF8.GetString(bytes).TrimStart('﻿');
        var pem = new X509Certificate2Collection();
        try
        {
            pem.ImportFromPem(text);
            var certificate = pem.Count switch
            {
                0 when text.Contains("-----BEGIN ", StringComparison.Ordinal) =>
                    throw new CertificateLoadException($"no CERTIFICATE block found in {fullPath}"),
                0 => X509CertificateLoader.LoadCertificate(bytes),
                1 => pem[0],
                _ => throw new CertificateLoadException(
                    $"{fullPath} contains {pem.Count} certificates; pass one certificate per invocation"),
            };
            return new CertificateFile(fullPath, certificate);
        }
        catch (CryptographicException)
        {
            throw new CertificateLoadException($"not a valid X.509 certificate: {fullPath}");
        }
    }

    private static byte[] ReadAllBytes(string fullPath)
    {
        try
        {
            return File.ReadAllBytes(fullPath);
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            throw new CertificateLoadException($"file not found: {fullPath}");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new CertificateLoadException($"cannot read {fullPath}: {e.Message}");
        }
    }
}
