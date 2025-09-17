using Microsoft.AspNetCore.Mvc.Testing;

namespace Inma.Tests;
public class ApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    
    public ApiTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }
}
public class UnitTest1
{
    [Fact]
    public void Test1()
    {
    }
}