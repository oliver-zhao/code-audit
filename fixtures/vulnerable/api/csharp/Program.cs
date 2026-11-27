using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;

internal static class ApiSamples
{
    private static void Run(string query, string name)
    {
        var conn = new SqlConnection("Server=localhost;");
        var cmd = new SqlCommand(query, conn);
        var info = new ProcessStartInfo("ls");
        Process.Start(info);
        var path = Path.Combine("/data", name);
        System.Console.WriteLine(path + cmd + info);
    }
}
