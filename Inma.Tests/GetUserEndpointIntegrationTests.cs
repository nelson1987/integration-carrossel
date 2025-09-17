using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.IdentityModel.Tokens;
using Shouldly;

namespace Inma.Tests;

public static class Configurations
{
    public static string Key { get; set; } = "nelson#123456";
}

public class ApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    protected readonly HttpClient Client;

    protected ApiTests(WebApplicationFactory<Program> factory)
    {
        Client = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
            });
        }).CreateClient();
    }
}

public class GetUserEndpointIntegrationTests : ApiTests
{
    public GetUserEndpointIntegrationTests(WebApplicationFactory<Program> factory) : base(factory)
    {
    }

    [Fact]
    public async Task GetUser_WithValidToken_ReturnsUser()
    {
        // Arrange
        var token = GenerateValidToken();
        Client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        // Act - Fazemos a requisição
        var response = await Client.GetAsync("/users/1");

        // Assert - Verificamos se deu bom
        response.EnsureSuccessStatusCode();

        var user = await response.Content
            .ReadFromJsonAsync<GetUserResponse>();

        user.ShouldNotBeNull();
        user.Id.ShouldBe(1);
    }

    [Fact]
    public async Task GetUser_WithoutToken_ReturnsUnauthorized()
    {
        // Act - Sem token, vida loka
        var response = await Client.GetAsync("/users/1");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetUser_WithExpiredToken_ReturnsUnauthorized()
    {
        // Arrange
        var expiredToken = GenerateExpiredToken();
        Client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", expiredToken);

        // Act & Assert
        var response = await Client.GetAsync("/users/1");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetUser_WithValidToken_NotFound_Returns404()
    {
        var expiredToken = GenerateValidToken();
        Client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", expiredToken);
        // Act
        var response = await Client.GetAsync("/users/999");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    private string GenerateValidToken()
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        // Usar a MESMA chave que a API usa
        var key = Encoding.ASCII.GetBytes(Settings.Secret);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new(ClaimTypes.Name, "testuser"),
                new(ClaimTypes.Role, "Admin")
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials =
                new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private string GenerateExpiredToken()
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        // Usar a MESMA chave que a API usa
        var key = Encoding.ASCII.GetBytes(Settings.Secret);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, "testuser"),
                new Claim(ClaimTypes.Role, "Admin")
            }),
            Expires = DateTime.UtcNow.AddMilliseconds(1), // Token já expirado
            SigningCredentials = new(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        return tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));

    }
}

public class PostUserEndpointIntegrationTests : ApiTests
{
    public PostUserEndpointIntegrationTests(WebApplicationFactory<Program> factory) : base(factory)
    {
    }

    [Fact]
    public async Task CreateUser_WithValidToken_ReturnsCreated()
    {
        // Arrange
        var token = GenerateTestToken();
        Client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
        
        var newUser = new CreateUserCommand(1);

        // Act
        var response = await Client.PostAsJsonAsync("/users", newUser);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Created);
    }

    [Fact]
    public async Task CreateUser_WithoutToken_ReturnsUnauthorized()
    {
        // Arrange
        var newUser = new CreateUserCommand(1);

        // Act
        var response = await Client.PostAsJsonAsync("/users", newUser);

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    private string GenerateTestToken()
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(Settings.Secret);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new(ClaimTypes.Name, "testuser"),
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