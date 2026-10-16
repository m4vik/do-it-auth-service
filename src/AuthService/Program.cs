using System.Security.Claims;
using System.Security.Cryptography;
using AuthService.Configuration;
using AuthService.Features;
using AuthService.Features.Auth;
using AuthService.Features.Verification;
using AuthService.Infrastructure;
using AuthService.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);
if (args.Contains("--init-secrets"))
{
    var directory = builder.Configuration["SecretsDirectory"] ?? "/secrets";
    Directory.CreateDirectory(directory);
    foreach (var name in new[] { "signing-key", "code-key" })
    {
        var path = Path.Combine(directory, name);
        if (!File.Exists(path)) await File.WriteAllTextAsync(path, Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)));
    }
    return;
}

foreach (var (setting, file) in new[] { ("SigningKey", "signing-key"), ("CodeKey", "code-key") })
{
    var directory = builder.Configuration["SecretsDirectory"];
    if (string.IsNullOrEmpty(builder.Configuration[$"Auth:{setting}"]) && directory is not null)
        builder.Configuration[$"Auth:{setting}"] = File.ReadAllText(Path.Combine(directory, file)).Trim();
}
builder.Services.AddOptions<AuthOptions>().BindConfiguration("Auth")
    .Validate(x => x.SigningKey.Length >= 64 && x.CodeKey.Length >= 64 && x.SigningKey != x.CodeKey, "Provide distinct signing and code keys (64+ characters).")
    .Validate(x => x.AccessMinutes > 0 && x.SessionDays > 0 && x.ContactCodeMinutes > 0
        && x.FactorCodeMinutes > 0 && x.CodeAttempts > 0 && x.SendCooldownSeconds > 0, "Auth limits must be positive.")
    .ValidateOnStart();
builder.Services.AddDbContext<AuthDbContext>(options => options.UseNpgsql(
    builder.Configuration.GetConnectionString("Postgres") ?? throw new InvalidOperationException("Postgres connection is missing.")));
builder.Services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect(
    builder.Configuration.GetConnectionString("Redis") ?? throw new InvalidOperationException("Redis connection is missing.")));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<Tokens>();
builder.Services.AddSingleton<ICodeSender, LogCodeSender>();
builder.Services.AddSingleton<ChallengeStore>();
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
builder.Services.AddScoped<AccountService>();
builder.Services.AddScoped<SessionService>();
builder.Services.AddScoped<VerificationService>();
builder.Services.AddControllers().ConfigureApiBehaviorOptions(options =>
    options.InvalidModelStateResponseFactory = _ => new BadRequestObjectResult(
        new { error = new { code = "invalid_request", message = "Check required fields and their formats." } }));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<Tokens>((options, tokens) =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = tokens.Validation("access");
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var principal = context.Principal!;
                if (!Tokens.HasRequiredClaims(principal, "access")
                    || !Guid.TryParse(principal.FindFirstValue("sub"), out var userId)
                    || !Guid.TryParse(principal.FindFirstValue("sid"), out var sessionId))
                {
                    context.Fail("Invalid token claims."); return;
                }
                var db = context.HttpContext.RequestServices.GetRequiredService<AuthDbContext>();
                var now = DateTimeOffset.UtcNow;
                var valid = await db.Sessions.AsNoTracking().AnyAsync(s => s.Id == sessionId && s.UserId == userId
                    && s.RevokedAt == null && s.ExpiresAt > now && db.Users.Any(u => u.Id == userId && u.IsActive),
                    context.HttpContext.RequestAborted);
                if (!valid) context.Fail("Session is no longer active.");
            },
            OnChallenge = async context =>
            {
                context.HandleResponse();
                context.Response.StatusCode = 401;
                context.Response.Headers.WWWAuthenticate = "Bearer";
                await context.Response.WriteAsJsonAsync(new { error = new { code = "unauthorized", message = "Authentication required." } });
            }
        };
    });
builder.Services.AddAuthorization();
var app = builder.Build();

if (args.Contains("--migrate"))
{
    using var scope = app.Services.CreateScope();
    await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Database.MigrateAsync();
    return;
}

app.Use(async (context, next) =>
{
    context.Response.Headers.CacheControl = "no-store";
    try { await next(context); }
    catch (ApiException error)
    {
        context.Response.StatusCode = error.Status;
        await context.Response.WriteAsJsonAsync(new { error = new { code = error.Code, message = error.Message } });
    }
    catch (Exception error) when (StorageErrors.IsUnavailable(error))
    {
        context.Response.StatusCode = 503;
        await context.Response.WriteAsJsonAsync(new { error = new { code = "storage_unavailable", message = "Required storage is temporarily unavailable." } });
    }
    catch (Exception error) when (error is not OperationCanceledException)
    {
        app.Logger.LogError("Request failed: {ErrorType}, trace {TraceId}", error.GetType().Name, context.TraceIdentifier);
        context.Response.StatusCode = 500;
        await context.Response.WriteAsJsonAsync(new { error = new { code = "internal_error", message = "An unexpected error occurred." } });
    }
});
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();

public partial class Program;
