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

        // Remove BOM if present. PemEncoding needs -----BEGIN at the start of a line,
        // and Encoding.UTF8.GetString preserves the BOM as U+FEFF.
        text = text.TrimStart('\uFEFF');

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
