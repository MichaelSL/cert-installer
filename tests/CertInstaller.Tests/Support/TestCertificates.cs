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
