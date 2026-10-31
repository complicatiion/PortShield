using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace PortShield.Platform.Windows;

/// <summary>Authenticode signature of executables (WinVerifyTrust): startup entries and programs.</summary>
public static class Authenticode
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    /// <summary>True when the file has a valid, trusted signature whose subject contains <paramref name="organization"/>.</summary>
    public static bool IsSignedBy(string file, string organization)
    {
        if (!IsTrusted(file))
        {
            return false;
        }

        try
        {
#pragma warning disable SYSLIB0057 // Reading the signer of a signed file; the signature itself was verified above.
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(file));
#pragma warning restore SYSLIB0057
            return cert.Subject.Contains($"O={organization}", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Signature state and signer (CN or O) of a file; signer is null when unsigned.</summary>
    public static (bool Trusted, string? Signer) GetSignature(string file)
    {
        if (!File.Exists(file))
        {
            return (false, null);
        }

        string? signer = null;
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(file));
#pragma warning restore SYSLIB0057
            signer = cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch (Exception)
        {
            return (false, null);
        }

        return (IsTrusted(file), signer);
    }

    private static bool IsTrusted(string file)
    {
        var fileInfo = new WinTrustFileInfo
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            FilePath = file
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
            var data = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = 2,            // WTD_UI_NONE
                RevocationChecks = 0,    // WTD_REVOKE_NONE
                UnionChoice = 1,         // WTD_CHOICE_FILE
                FileInfo = fileInfoPtr,
                StateAction = 0,
                ProvFlags = 0x00000010   // WTD_REVOCATION_CHECK_NONE (offline-friendly)
            };

            var action = GenericVerifyV2;
            return WinVerifyTrust(IntPtr.Zero, ref action, ref data) == 0;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPtr);
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        [MarshalAs(UnmanagedType.LPWStr)] public string FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        [MarshalAs(UnmanagedType.LPWStr)] public string? UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WinTrustData data);
}
