using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class InvoicesController : ControllerBase
{
    private readonly AppDbContext _context;

    public InvoicesController(AppDbContext context) => _context = context;

    [HttpPost]
    public IActionResult Create([FromBody] Invoice invoice)
    {
        _context.Invoices.Add(invoice);
        _context.SaveChanges();
        return Ok(invoice);
    }

    [Authorize]
    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        var invoice = await _context.Invoices.FindAsync(id);
        _context.Invoices.Remove(invoice);
        await _context.SaveChangesAsync();
        return NoContent();
    }
}
