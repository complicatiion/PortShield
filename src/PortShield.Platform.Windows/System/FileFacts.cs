using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;

namespace PortShield.Platform.Windows;

/// <summary>Facts about a program file shown in the lists and written to exports.</summary>
public sealed record FileFacts(bool Exists, string? Description, string? Company, string? Version, long Size, DateTime? Modified)
{
    public static readonly FileFacts Missing = new(false, null, null, null, 0, null);
}

/// <summary>Version info, signature and SHA-256 of program files, cached per path and change time.</summary>
public static class FileInspector
{
    private static readonly ConcurrentDictionary<string, (DateTime Stamp, FileFacts Facts)> FactsCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, (DateTime Stamp, string Hash)> HashCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, (DateTime Stamp, bool Trusted, string? Signer)> SignatureCache = new(StringComparer.OrdinalIgnoreCase);

    public static FileFacts Read(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return FileFacts.Missing;
            }

            var stamp = info.LastWriteTimeUtc;
            if (FactsCache.TryGetValue(path, out var cached) && cached.Stamp == stamp)
            {
                return cached.Facts;
            }

            var version = FileVersionInfo.GetVersionInfo(path);
            var facts = new FileFacts(true, Clean(version.FileDescription), Clean(version.CompanyName), Clean(version.ProductVersion ?? version.FileVersion),
                info.Length, info.LastWriteTime);
            FactsCache[path] = (stamp, facts);
            return facts;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return FileFacts.Missing;
        }
    }

    public static bool Exists(string path)
    {
        try
        {
            return File.Exists(path);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Lower-case SHA-256 of the file; null when it does not exist or cannot be read.</summary>
    public static string? Sha256(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return null;
            }

            if (HashCache.TryGetValue(path, out var cached) && cached.Stamp == info.LastWriteTimeUtc)
            {
                return cached.Hash;
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
            var hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            HashCache[path] = (info.LastWriteTimeUtc, hash);
            return hash;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>Authenticode state and signer (offline check, no revocation lookup).</summary>
    public static (bool Trusted, string? Signer) Signature(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return (false, null);
            }

            if (SignatureCache.TryGetValue(path, out var cached) && cached.Stamp == info.LastWriteTimeUtc)
            {
                return (cached.Trusted, cached.Signer);
            }

            var (trusted, signer) = Authenticode.GetSignature(path);
            SignatureCache[path] = (info.LastWriteTimeUtc, trusted, signer);
            return (trusted, signer);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return (false, null);
        }
    }

    private static string? Clean(string? value)
    {
        var v = value?.Trim();
        return string.IsNullOrEmpty(v) ? null : v;
    }
}
