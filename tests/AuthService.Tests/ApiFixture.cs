using System.Collections.Concurrent;
using AuthService.Features.Verification;
using AuthService.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using StackExchange.Redis;

namespace AuthService.Tests;

public sealed class CapturingSender : ICodeSender
{
    public ConcurrentDictionary<Guid, string> Codes { get; } = new();
    public ConcurrentDictionary<Guid, string> Channels { get; } = new();
    public Task Send(string channel, string recipient, string purpose, Guid challengeId, string code)
    {
        Codes[challengeId] = code;
        Channels[challengeId] = channel;
        return Task.CompletedTask;
    }
}

public sealed class ApiFixture : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly string database = "auth_test_" + Guid.NewGuid().ToString("N");
    private string adminConnection = "";
    public CapturingSender Sender { get; } = new();
    public IConnectionMultiplexer Redis => Services.GetRequiredService<IConnectionMultiplexer>();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, config) =>
        {
            var connection = new NpgsqlConnectionStringBuilder(adminConnection) { Database = database };
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Postgres"] = connection.ConnectionString,
                ["ConnectionStrings:Redis"] = Environment.GetEnvironmentVariable("TEST_REDIS") ?? "localhost:6379",
                ["Auth:SigningKey"] = new string('t', 64), ["Auth:CodeKey"] = new string('c', 64),
                ["Logging:LogLevel:Default"] = "Warning"
            });
        });
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<ICodeSender>();
            services.AddSingleton<ICodeSender>(Sender);
        });
    }

    public async Task InitializeAsync()
    {
        adminConnection = Environment.GetEnvironmentVariable("TEST_POSTGRES")
            ?? "Host=localhost;Database=postgres;Username=auth;Password=local-demo-password";
        await using var connection = new NpgsqlConnection(adminConnection);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand($"CREATE DATABASE {database}", connection);
        await command.ExecuteNonQueryAsync();
        using var scope = Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Database.MigrateAsync();
    }

    async Task IAsyncLifetime.DisposeAsync()
    {
        await base.DisposeAsync();
        NpgsqlConnection.ClearAllPools();
        await using var connection = new NpgsqlConnection(adminConnection);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand($"DROP DATABASE IF EXISTS {database} WITH (FORCE)", connection);
        await command.ExecuteNonQueryAsync();
    }
}
