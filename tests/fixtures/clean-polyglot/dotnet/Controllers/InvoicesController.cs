using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class InvoicesController : ControllerBase
{
    private readonly AppDbContext _context;

    public InvoicesController(AppDbContext context) => _context = context;

    [HttpPost]
    public IActionResult Create([FromBody] InvoiceRequest request)
    {
        var owner = User.FindFirstValue(ClaimTypes.NameIdentifier);
        _context.Invoices.Add(request.ToInvoice(owner));
        _context.SaveChanges();
        return Ok();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        var owner = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var invoice = await _context.Invoices.FirstOrDefaultAsync(i => i.Id == id && i.UserId == owner);
        if (invoice is null) return NotFound();
        _context.Invoices.Remove(invoice);
        await _context.SaveChangesAsync();
        return NoContent();
    }
}
