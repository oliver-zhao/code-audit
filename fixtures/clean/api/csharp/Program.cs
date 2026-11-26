using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;

internal static class ApiSamples
{
    private static void Main()
    {
        var conn = new SqlConnection("Server=localhost;");
        var cmd = new SqlCommand("SELECT 1", conn);
        var info = new ProcessStartInfo("ls");
        Process.Start(info);
        var path = Path.Combine("/data", "static.txt");
        System.Console.WriteLine(path + cmd + info);
    }
}
