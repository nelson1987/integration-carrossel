using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Inma.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

var key = Encoding.ASCII.GetBytes("fedaf7d8863b48e197b9287d492b708e");
var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddAuthorization()
    .AddAuthentication(x =>
    {
        x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(x =>
    {
        x.RequireHttpsMetadata = false;
        x.SaveToken = true;
        x.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero
        };
    });
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapPost("/login", ([FromServices] LoginService service, [FromBody] LoginRequest login) =>
{
    if (!service.IsValidUser(login))
        return Results.Unauthorized();

    var token = service.GenerateJwtToken(login.Username);
    return Results.Ok(new { Token = token });
});
app.MapGet("/users/{id}", (int id) =>
    id != 1
        ? Results.NotFound()
        : Results.Ok(new GetUserResponse(id, "João Dev"))
).RequireAuthorization();

app.MapPost("/users", (CreateUserCommand user) =>
        Results.Created($"/users/{user.Id}", user))
    .RequireAuthorization();

await app.RunAsync();

namespace Inma.Api
{
    public partial class Program
    {
    }

    public record CreateUserCommand(int Id);

    public record LoginRequest(string Username);
    public record GetUserResponse(int Id, string Name);
    public static class Settings
    {
        public static readonly string Secret = "fedaf7d8863b48e197b9287d492b708e";
    }

    public class LoginService
    {
        public bool IsValidUser(LoginRequest loginRequest)
        {
            return true;
        }

        public string GenerateJwtToken(string username)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(Settings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new(ClaimTypes.Name, username),
                    new(ClaimTypes.Role, "Admin")
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials =
                    new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}