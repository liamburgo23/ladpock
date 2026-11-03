using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

[Authorize]
[ApiController]
[Route("reports")]
public class ReportsController : ControllerBase
{
    private readonly SqlConnection connection;

    public ReportsController(SqlConnection connection) => this.connection = connection;

    [HttpGet("{name}")]
    public IActionResult Get(string name, [FromBody] string body)
    {
        var command = new SqlCommand("SELECT * FROM reports WHERE name = @name", connection);
        command.Parameters.AddWithValue("@name", name);
        var report = JsonSerializer.Deserialize<Report>(body);
        return Ok(report);
    }
}

public record Report(string Name);
