using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

[ApiController]
[Route("reports")]
public class ReportsController : ControllerBase
{
    [HttpGet("{name}")]
    public IActionResult Get(string name)
    {
        var command = new SqlCommand($"SELECT * FROM reports WHERE name = '{name}'");
        Process.Start("cmd.exe", "/c type " + name);
        var formatter = new BinaryFormatter();
        return Ok();
    }
}
