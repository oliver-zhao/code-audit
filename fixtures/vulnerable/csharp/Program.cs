using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Xml;

internal static class VulnerableProgram
{
    private static void Main(string[] args)
    {
        var name = args[0];
        var conn = new SqlConnection("Server=localhost;Database=app;");
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
        Process.Start("sh", "-c " + name);
        var formatter = new BinaryFormatter();
        var path = Path.Combine("/data", name);
        var hash = MD5.Create();
        var rng = new Random();
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
    }
}
