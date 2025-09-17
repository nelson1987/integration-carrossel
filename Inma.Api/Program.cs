using Inma.Api;

var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

app.MapGet("/users/{id}", (int id) =>
    new { Id = id, Name = "João Dev" });

app.MapPost("/users", (CreateUserCommand user) =>
    Results.Created($"/users/{user.Id}", user));

await app.RunAsync();

namespace Inma.Api
{
    public record CreateUserCommand(int Id);
}