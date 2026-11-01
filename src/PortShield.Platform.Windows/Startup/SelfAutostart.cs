using System.Security;
using System.Text;
using System.Xml.Linq;
using PortShield.Core.Diagnostics;

namespace PortShield.Platform.Windows;

/// <summary>
/// "Start PortShield in the tray at sign-in" via the Task Scheduler: one task per user with highest privileges.
/// (Elevated apps are silently skipped in the Run key, so a task is the reliable way.)
/// </summary>
public static class SelfAutostart
{
    private const string Folder = @"\PortShield\";

    public static string TaskName(string user) =>
        Folder + "Tray " + string.Concat(user.Select(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '_'));

    public static bool IsRegistered(string user) => RegisteredCommand(user) is not null;

    /// <summary>Executable the user's task starts (null = no task).</summary>
    public static string? RegisteredCommand(string user)
    {
        var run = ProcessRunner.Run("schtasks.exe", ["/Query", "/TN", TaskName(user), "/XML"], TimeSpan.FromSeconds(15));
        if (!run.Success)
        {
            return null;
        }

        try
        {
            var start = run.Output.IndexOf('<');
            var doc = XDocument.Parse(run.Output[start..]);
            return doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Command")?.Value;
        }
        catch (Exception)
        {
            return "";
        }
    }

    public static bool Register(string user, string executable)
    {
        var xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <Author>PortShield</Author>
                <Description>Starts PortShield in the system tray at sign-in.</Description>
              </RegistrationInfo>
              <Triggers>
                <LogonTrigger>
                  <Enabled>true</Enabled>
                  <UserId>{SecurityElement.Escape(user)}</UserId>
                  <Delay>PT10S</Delay>
                </LogonTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>{SecurityElement.Escape(user)}</UserId>
                  <LogonType>InteractiveToken</LogonType>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <AllowHardTerminate>true</AllowHardTerminate>
                <StartWhenAvailable>false</StartWhenAvailable>
                <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                <IdleSettings>
                  <StopOnIdleEnd>false</StopOnIdleEnd>
                  <RestartOnIdle>false</RestartOnIdle>
                </IdleSettings>
                <AllowStartOnDemand>true</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <Hidden>false</Hidden>
                <RunOnlyIfIdle>false</RunOnlyIfIdle>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>7</Priority>
              </Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>{SecurityElement.Escape(executable)}</Command>
                  <Arguments>--tray</Arguments>
                  <WorkingDirectory>{SecurityElement.Escape(Path.GetDirectoryName(executable) ?? "")}</WorkingDirectory>
                </Exec>
              </Actions>
            </Task>
            """;

        var file = Path.Combine(Path.GetTempPath(), $"portshield-task-{Environment.ProcessId}.xml");
        try
        {
            File.WriteAllText(file, xml, Encoding.Unicode);
            return ProcessRunner.Run("schtasks.exe", ["/Create", "/TN", TaskName(user), "/XML", file, "/F"], TimeSpan.FromSeconds(20)).Success;
        }
        finally
        {
            try
            {
                File.Delete(file);
            }
            catch (IOException)
            {
            }
        }
    }

    public static bool Unregister(string user) =>
        !IsRegistered(user) || ProcessRunner.Run("schtasks.exe", ["/Delete", "/TN", TaskName(user), "/F"], TimeSpan.FromSeconds(15)).Success;

    /// <summary>Removes the tray tasks of all users (uninstall).</summary>
    public static int UnregisterAll()
    {
        var run = ProcessRunner.Run("schtasks.exe", ["/Query", "/FO", "CSV", "/NH"], TimeSpan.FromSeconds(30));
        var removed = 0;
        foreach (var line in run.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var name = line.Split(',')[0].Trim('"');
            if (name.StartsWith(Folder, StringComparison.OrdinalIgnoreCase)
                && ProcessRunner.Run("schtasks.exe", ["/Delete", "/TN", name, "/F"], TimeSpan.FromSeconds(15)).Success)
            {
                removed++;
            }
        }

        return removed;
    }
}
