using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading.Tasks;
using System.Xml;
using Dapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace SafeShop.Controllers;

// The safe way to write the seeds of fixtures/vulnerable/csharp/WebApp.
// Comments and strings that only mention dangerous APIs are not code:
// Process.Start("cmd.exe", "/c " + format) and FromSqlRaw($"... = '{term}'").
[ApiController]
[Route("api/orders")]
[AutoValidateAntiforgeryToken]
public class OrdersController : Controller
{
    private static readonly Dictionary<string, Type> Handlers = new() { ["csv"] = typeof(object) };
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
            "SELECT * FROM Orders WHERE Customer = @customer",
            _connection);
        cmd.Parameters.AddWithValue("@customer", customer);
        return Ok(cmd.ExecuteReader());
    }

    [HttpGet("search")]
    public async Task<IActionResult> Search([FromQuery] string term)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM Orders WHERE Title LIKE @term";
        cmd.Parameters.AddWithValue("@term", "%" + term + "%");
        var orders = await _db.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE Title = {term}").ToListAsync();
        var recent = await _db.Orders.FromSql($"SELECT * FROM Orders WHERE Owner = {term}").ToListAsync();
        await _db.Database.ExecuteSqlAsync($"DELETE FROM Carts WHERE Owner = {term}");
        await _db.Database.ExecuteSqlRawAsync("DELETE FROM Carts WHERE Owner = {0}", term);
        var rows = _connection.Query<Order>("SELECT * FROM Orders WHERE Owner = @Owner", new { Owner = term });
        const string sql = "UPDATE Orders SET Note = @note WHERE Id = 1";
        var message = "Searching for " + term;
        return Ok(new { orders, recent, rows, sql, message });
    }

    [HttpPost("export")]
    public IActionResult Export([FromQuery] string format)
    {
        if (format != "csv" && format != "json")
        {
            return BadRequest();
        }
        var info = new ProcessStartInfo("exporter");
        info.ArgumentList.Add("--format");
        info.ArgumentList.Add(format);
        return Ok(info.FileName);
    }

    [HttpGet("login")]
    public IActionResult Login([FromQuery] string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        return LocalRedirect("/");
    }

    [HttpPost("upload")]
    public async Task<IActionResult> Upload([FromForm] IFormFile file)
    {
        var storedName = Guid.NewGuid().ToString("N") + Path.GetExtension(Path.GetFileName(file.FileName));
        var path = Path.Combine("/srv/uploads", storedName);
        using var stream = System.IO.File.Create(path);
        await file.CopyToAsync(stream);
        return Ok();
    }

    [HttpPost("import")]
    public IActionResult Import(string archive)
    {
        var root = Path.GetFullPath("/srv/import");
        using var zip = ZipFile.OpenRead(archive);
        foreach (var entry in zip.Entries)
        {
            var target = Path.GetFullPath(Path.Combine(root, entry.FullName));
            if (!target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                return BadRequest();
            }
            entry.ExtractToFile(target);
        }
        return Ok();
    }

    [HttpPost("plugin")]
    public IActionResult Plugin(string name)
    {
        return Handlers.TryGetValue(name, out var type) ? Ok(type.Name) : NotFound();
    }
}
