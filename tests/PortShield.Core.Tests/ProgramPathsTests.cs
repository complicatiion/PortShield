using PortShield.Core.Rules;

namespace PortShield.Core.Tests;

public class ProgramPathsTests
{
    private static string? FakeVariables(string name) => name switch
    {
        "ProgramFiles" => @"C:\Program Files",
        "ProgramW6432" => @"C:\Program Files",
        "ProgramFiles(x86)" => @"C:\Program Files (x86)",
        "ProgramData" => @"C:\ProgramData",
        "LOCALAPPDATA" => @"C:\Users\sven\AppData\Local",
        "APPDATA" => @"C:\Users\sven\AppData\Roaming",
        "USERPROFILE" => @"C:\Users\sven",
        "SystemRoot" => @"C:\Windows",
        _ => null
    };

    [Theory]
    [InlineData(@"C:\Program Files\Adobe\Photoshop.exe", @"%ProgramFiles%\Adobe\Photoshop.exe")]
    [InlineData(@"C:\Program Files (x86)\Adobe\Acrobat 10.0\Acrobat\Acrobat.exe", @"%ProgramFiles(x86)%\Adobe\Acrobat 10.0\Acrobat\Acrobat.exe")]
    [InlineData(@"C:\Users\sven\AppData\Local\Discord\app.exe", @"%LOCALAPPDATA%\Discord\app.exe")]
    [InlineData(@"D:\Tools\tool.exe", @"D:\Tools\tool.exe")]
    public void Portable_paths(string path, string expected) =>
        Assert.Equal(expected, ProgramPaths.ToPortable(path, FakeVariables));

    [Fact]
    public void Program_Files_x86_is_not_mistaken_for_Program_Files() =>
        Assert.StartsWith("%ProgramFiles(x86)%", ProgramPaths.ToPortable(@"C:\Program Files (x86)\a.exe", FakeVariables));

    [Theory]
    [InlineData(@"C:\X\unins000.exe", true)]
    [InlineData(@"C:\X\Setup.exe", true)]
    [InlineData(@"C:\X\SnagitPI64.exe", false)]
    [InlineData(@"C:\X\vc_redist.x64.exe", true)]
    [InlineData(@"C:\X\Uninstall Foo.exe", true)]
    [InlineData(@"C:\X\photoshop.exe", false)]
    [InlineData(@"C:\X\updater.exe", false)]
    public void Installer_detection(string path, bool expected) => Assert.Equal(expected, ProgramPaths.IsInstaller(path));

    [Fact]
    public void Same_ignores_case_quotes_and_separators()
    {
        Assert.True(ProgramPaths.Same(@"""C:\Program Files\A\b.exe""", @"c:/program files/a/B.EXE"));
        Assert.False(ProgramPaths.Same(@"C:\A\b.exe", @"C:\A\c.exe"));
    }

    [Fact]
    public void File_name_and_directory_of_windows_paths()
    {
        Assert.Equal("b.exe", ProgramPaths.FileName(@"C:\A\b.exe"));
        Assert.Equal(@"C:\A", ProgramPaths.Directory(@"C:\A\b.exe"));
    }

    [Fact]
    public void Wildcards_resolve_existing_files()
    {
        var root = Path.Combine(Path.GetTempPath(), "ps-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "Adobe Photoshop 2021"));
            Directory.CreateDirectory(Path.Combine(root, "Adobe Photoshop 2024"));
            Directory.CreateDirectory(Path.Combine(root, "Other"));
            File.WriteAllText(Path.Combine(root, "Adobe Photoshop 2021", "Photoshop.exe"), "");
            File.WriteAllText(Path.Combine(root, "Adobe Photoshop 2024", "Photoshop.exe"), "");
            File.WriteAllText(Path.Combine(root, "Other", "Photoshop.exe"), "");

            var found = ProgramPaths.Resolve(Path.Combine(root, "Adobe Photoshop *", "Photoshop.exe"));
            Assert.Equal(2, found.Count);

            var exes = ProgramPaths.Resolve(Path.Combine(root, "Other", "*.exe"));
            Assert.Single(exes);

            Assert.Empty(ProgramPaths.Resolve(Path.Combine(root, "Missing *", "x.exe")));
            Assert.Equal(3, ProgramPaths.FindExecutables(root, recursive: true).Count);
            Assert.Empty(ProgramPaths.FindExecutables(root, recursive: false));
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
}
