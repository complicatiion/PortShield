using System.Globalization;
using System.Security;
using System.Text;
using PortShield.Core.Diagnostics;

namespace PortShield.Platform.Windows;

/// <summary>
/// One-shot task that blocks temporarily allowed rules again when PortShield is not running at that moment
/// ("PortShield.exe --restore-temporary" as SYSTEM). The running app restores on its own; the task is the safety net
/// (also after a restart: the task runs as soon as possible when the time was missed).
/// </summary>
public static class TemporaryTask
{
    public const string TaskName = @"\PortShield\Restore temporary rules";

    public static bool Schedule(DateTime localTime, string executable)
    {
        var start = localTime.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <Author>PortShield</Author>
                <Description>Blocks rules that PortShield allowed temporarily again.</Description>
              </RegistrationInfo>
              <Triggers>
                <TimeTrigger>
                  <StartBoundary>{start}</StartBoundary>
                  <Enabled>true</Enabled>
                </TimeTrigger>
                <BootTrigger>
                  <Enabled>true</Enabled>
                  <Delay>PT1M</Delay>
                </BootTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>S-1-5-18</UserId>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <AllowHardTerminate>true</AllowHardTerminate>
                <StartWhenAvailable>true</StartWhenAvailable>
                <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                <AllowStartOnDemand>true</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <Hidden>false</Hidden>
                <RunOnlyIfIdle>false</RunOnlyIfIdle>
                <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
                <Priority>7</Priority>
              </Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>{SecurityElement.Escape(executable)}</Command>
                  <Arguments>--restore-temporary</Arguments>
                  <WorkingDirectory>{SecurityElement.Escape(Path.GetDirectoryName(executable) ?? "")}</WorkingDirectory>
                </Exec>
              </Actions>
            </Task>
            """;

        var file = Path.Combine(Path.GetTempPath(), $"portshield-temp-task-{Environment.ProcessId}.xml");
        try
        {
            File.WriteAllText(file, xml, Encoding.Unicode);
            return ProcessRunner.Run("schtasks.exe", ["/Create", "/TN", TaskName, "/XML", file, "/F"], TimeSpan.FromSeconds(20)).Success;
        }
        catch (IOException)
        {
            return false;
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

    public static void Remove() =>
        ProcessRunner.Run("schtasks.exe", ["/Delete", "/TN", TaskName, "/F"], TimeSpan.FromSeconds(15));
}
