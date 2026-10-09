using System.Diagnostics;

public class Storage
{
    public void RunTool(string arguments)
    {
        Process.Start("/usr/bin/tool", arguments);
    }

    public void Execute(string ignored)
    {
        Process.Start("/usr/bin/uptime");
    }
}
