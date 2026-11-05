var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var api = app.MapGroup("/api").RequireAuthorization();
api.MapGet("/profile", (ClaimsPrincipal user) => Results.Ok(user.Identity?.Name));

app.Run();
