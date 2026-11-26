using System;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Xml;

internal static class SafeProgram
{
    private static void Main(string[] args)
    {
        var name = args.Length > 0 ? args[0] : "guest";
        var conn = new SqlConnection("Server=localhost;Database=app;");
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        cmd.Parameters.AddWithValue("@name", name);
        var path = Path.Combine("/data", "static.txt");
        var hash = SHA256.Create();
        var nonce = RandomNumberGenerator.GetBytes(16);
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
        using var stream = File.OpenRead(path);
        GC.KeepAlive(new object[] { hash, nonce, settings, stream, cmd });
    }
}
