using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Shouldly;

namespace Inma.Tests;

public class ApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    protected readonly HttpClient Client;

    protected ApiTests(WebApplicationFactory<Program> factory)
    {
        Client = factory.CreateClient();
    }
}

public class GetUserEndpointIntegrationTests : ApiTests
{
    public GetUserEndpointIntegrationTests(WebApplicationFactory<Program> factory) : base(factory)
    {
    }

    [Fact]
    public async Task GetUser_ReturnsUser()
    {
        // Act - Fazemos a requisição
        var response = await Client.GetAsync("/users/1");

        // Assert - Verificamos se deu bom
        response.EnsureSuccessStatusCode();

        var user = await response.Content
            .ReadFromJsonAsync<CreateUserCommand>();
        
        user.ShouldNotBeNull();
        user.Id.ShouldBe(1);
    }
    [Fact]
    public async Task GetUser_NotFound_Returns404()
    {
        // Act
        var response = await Client.GetAsync("/users/999");
    
        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }
}

public class PostUserEndpointIntegrationTests : ApiTests
{
    public PostUserEndpointIntegrationTests(WebApplicationFactory<Program> factory) : base(factory)
    {
    }
    
    [Fact]
    public async Task CreateUser_ReturnsCreated()
    {
        // Arrange
        var newUser = new { Name = "Maria Dev", Email = "maria@dev.com" };
    
        // Act
        var response = await Client.PostAsJsonAsync("/users", newUser);
    
        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Created);
    }
}