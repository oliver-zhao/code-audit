using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Xml;
using Dapper;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.EntityFrameworkCore;

namespace VulnerableShop.Controllers;

// Seeded vulnerabilities for the built-in C# rules. Every hit is listed in
// fixtures/vulnerable/EXPECTED.json; do not move lines without updating it.
[ApiController]
[Route("api/orders")]
public class OrdersController : Controller
{
    private readonly ShopContext _db;
    private readonly SqlConnection _connection;

    public OrdersController(ShopContext db, SqlConnection connection)
    {
        _db = db;
        _connection = connection;
    }

    [HttpGet("by-customer")]
    public IActionResult ByCustomer([FromQuery] string customer)
    {
        var cmd = new SqlCommand(
            "SELECT * FROM Orders WHERE Customer = '" + customer + "'",
            _connection);
        return Ok(cmd.ExecuteReader());
    }

    [HttpGet("search")]
    public async Task<IActionResult> Search(string term, string sort)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = $"SELECT * FROM Orders WHERE Title LIKE '%{term}%'";
        var orders = await _db.Orders.FromSqlRaw($"SELECT * FROM Orders WHERE Title = '{term}'").ToListAsync();
        await _db.Database.ExecuteSqlRawAsync("DELETE FROM Carts WHERE Owner = " + term);
        var rows = _connection.Query<Order>("SELECT * FROM Orders ORDER BY " + sort);
        string sql = "UPDATE Orders SET Note = '" + term + "' WHERE Id = 1";
        return Ok(new { orders, rows, sql });
    }

    [HttpPost("export")]
    public IActionResult Export([FromQuery] string format, [FromQuery] string target)
    {
        Process.Start("cmd.exe", "/c export.bat " + format);
        var info = new ProcessStartInfo("exporter", $"--format {format} --out {target}");
        return Ok(info.FileName);
    }

    [HttpGet("directory")]
    public IActionResult Directory(string user)
    {
        var searcher = new DirectorySearcher();
        searcher.Filter = "(&(objectClass=user)(sAMAccountName=" + user + "))";
        var doc = new XmlDocument();
        doc.Load("customers.xml");
        var node = doc.SelectSingleNode("//customer[@name='" + user + "']");
        return Ok(new { searcher, node });
    }

    [HttpGet("login")]
    public IActionResult Login([FromQuery] string returnUrl)
    {
        return Redirect(returnUrl);
    }

    [HttpPost("upload")]
    public async Task<IActionResult> Upload([FromForm] IFormFile file)
    {
        var path = Path.Combine("/srv/uploads", file.FileName);
        using var stream = System.IO.File.Create(path);
        await file.CopyToAsync(stream);
        return Ok();
    }

    [HttpPost("import")]
    public IActionResult Import(string archive)
    {
        using var zip = ZipFile.OpenRead(archive);
        foreach (var entry in zip.Entries)
        {
            entry.ExtractToFile(Path.Combine("/srv/import", entry.FullName));
        }
        return Ok();
    }

    [HttpPost("plugin")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Plugin(string script)
    {
        var handler = Activator.CreateInstance(Type.GetType(Request.Query["handler"]));
        var result = await CSharpScript.EvaluateAsync(script);
        return Ok(new { handler, result });
    }

    [HttpGet("preview")]
    public IActionResult Preview()
    {
        return Content(new HtmlString(Request.Query["html"]).ToString(), "text/html");
    }
}
