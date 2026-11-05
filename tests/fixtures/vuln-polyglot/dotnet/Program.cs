var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapPost("/api/feedback", async (Feedback feedback, AppDbContext db) =>
{
    db.Feedback.Add(feedback);
    await db.SaveChangesAsync();
    return Results.Ok();
});

app.Run();
