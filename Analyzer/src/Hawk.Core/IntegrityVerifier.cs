using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace Hawk.Core;

/// <summary>
/// Independent re-verification of a .hawk session's seal: the container hash
/// against its <c>.sha256</c> sidecar, and every file inside the container
/// against the collector's <c>hashes.json</c>. Nothing is trusted on faith -
/// a session that cannot be verified is reported as such, never as "sealed".
/// </summary>
public static class IntegrityVerifier
{
    public const string Verified = "VERIFIED";
    public const string Failed = "FAILED";
    public const string Unverifiable = "UNVERIFIABLE";

    public sealed class Result
    {
        public string Status { get; set; } = Unverifiable;
        public string ContainerSha256 { get; set; } = "";
        public string? SidecarSha256 { get; set; }
        /// <summary>MATCH | MISMATCH | NO-SIDECAR</summary>
        public string ContainerCheck { get; set; } = "NO-SIDECAR";
        public bool HashesManifestPresent { get; set; }
        public int FilesVerified { get; set; }
        public List<string> Mismatched { get; set; } = [];
        public List<string> Missing { get; set; } = [];
        public List<string> Unlisted { get; set; } = [];
        public string VerifiedAtUtc { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

        public IEnumerable<string> Summary()
        {
            yield return $"integrity: {Status}";
            yield return $"  container sha256 {ContainerSha256} ({ContainerCheck}"
                         + (SidecarSha256 != null && ContainerCheck == "MISMATCH" ? $", sidecar says {SidecarSha256})" : ")");
            if (!HashesManifestPresent) { yield return "  hashes.json MISSING - per-file seal cannot be checked"; yield break; }
            yield return $"  files verified: {FilesVerified}, mismatched: {Mismatched.Count}, missing: {Missing.Count}, unlisted: {Unlisted.Count}";
            foreach (var f in Mismatched) yield return $"  MISMATCH  {f}";
            foreach (var f in Missing) yield return $"  MISSING   {f}";
            foreach (var f in Unlisted) yield return $"  UNLISTED  {f}";
        }
    }

    /// <summary>Verifies a .hawk. When <paramref name="extractedDir"/> is null the
    /// container is extracted to a temporary folder and removed afterwards.</summary>
    public static Result Verify(string hawkFile, string? extractedDir = null)
    {
        var result = new Result { ContainerSha256 = Sha256(hawkFile) };

        var sidecar = hawkFile + ".sha256";
        if (File.Exists(sidecar))
        {
            var first = File.ReadAllText(sidecar).Trim().Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries);
            result.SidecarSha256 = first.Length > 0 ? first[0].ToUpperInvariant() : "";
            result.ContainerCheck = result.SidecarSha256 == result.ContainerSha256 ? "MATCH" : "MISMATCH";
        }

        string? tempDir = null;
        try
        {
            if (extractedDir == null)
            {
                tempDir = Path.Combine(Path.GetTempPath(), "hawk_verify_" + Guid.NewGuid().ToString("N")[..8]);
                ZipFile.ExtractToDirectory(hawkFile, tempDir);
                extractedDir = tempDir;
            }
            CheckFiles(extractedDir, result);
        }
        finally
        {
            if (tempDir != null) try { Directory.Delete(tempDir, true); } catch { /* best effort */ }
        }

        var fileSealOk = result.HashesManifestPresent && result.Mismatched.Count == 0
                         && result.Missing.Count == 0 && result.Unlisted.Count == 0;
        result.Status = result.ContainerCheck == "MISMATCH" || result.Mismatched.Count > 0
                        || result.Missing.Count > 0 || result.Unlisted.Count > 0
            ? Failed
            : fileSealOk && result.ContainerCheck == "MATCH" ? Verified : Unverifiable;
        return result;
    }

    private static void CheckFiles(string root, Result result)
    {
        var hashesPath = Path.Combine(root, "hashes.json");
        if (!File.Exists(hashesPath)) return;
        result.HashesManifestPresent = true;

        // Collector writes { files: [ {path, sha256}, ... ] }; a one-file session
        // serializes `files` as a bare object (PowerShell ConvertTo-Json), so accept both.
        using var doc = JsonDocument.Parse(File.ReadAllText(hashesPath));
        var expected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (doc.RootElement.TryGetProperty("files", out var files))
        {
            var entries = files.ValueKind == JsonValueKind.Array ? files.EnumerateArray().ToList() : [files];
            foreach (var e in entries)
            {
                var p = e.GetProperty("path").GetString();
                var h = e.GetProperty("sha256").GetString();
                if (p != null && h != null) expected[Normalize(p)] = h.ToUpperInvariant();
            }
        }

        foreach (var (rel, hash) in expected.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var full = Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(full)) { result.Missing.Add(rel); continue; }
            if (Sha256(full) == hash) result.FilesVerified++;
            else result.Mismatched.Add(rel);
        }

        foreach (var full in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            var rel = Normalize(Path.GetRelativePath(root, full));
            if (rel.Equals("hashes.json", StringComparison.OrdinalIgnoreCase)) continue;
            if (!expected.ContainsKey(rel)) result.Unlisted.Add(rel);
        }
        result.Unlisted.Sort(StringComparer.Ordinal);
    }

    private static string Normalize(string p) => p.Replace('\\', '/').TrimStart('/');

    private static string Sha256(string path)
    {
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(fs));
    }

    public static string ToJson(Result r) => JsonSerializer.Serialize(r);
}
