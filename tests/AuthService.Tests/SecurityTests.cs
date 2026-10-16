using AuthService.Configuration;
using AuthService.Features;
using AuthService.Infrastructure;
using AuthService.Security;
using Microsoft.Extensions.Options;

namespace AuthService.Tests;

public sealed class SecurityTests
{
    [Theory]
    [InlineData("email", " USER@Example.com ", "user@example.com")]
    [InlineData("phone", "+1 (202) 555-0123", "+12025550123")]
    public void IdentifiersAreNormalized(string type, string input, string expected) =>
        Assert.Equal(expected, Identifiers.Normalize(type, input).Value);

    [Theory]
    [InlineData("email", "not-an-email")]
    [InlineData("email", "Name <user@example.com>")]
    [InlineData("phone", "2025550123")]
    [InlineData("phone", "+123")]
    [InlineData("other", "user@example.com")]
    public void InvalidIdentifiersAreRejected(string type, string input) =>
        Assert.Throws<ApiException>(() => Identifiers.Normalize(type, input));

    [Fact]
    public void RefreshRequiresCorrectSignaturePurposeAndLifetime()
    {
        var tokens = MakeTokens('a');
        var session = new LoginSession { UserId = Guid.NewGuid(), ExpiresAt = DateTimeOffset.UtcNow.AddDays(1) };
        var pair = tokens.Issue(session);
        Assert.Equal((session.UserId, session.Id), tokens.ReadRefresh(pair.RefreshToken));
        Assert.Throws<ApiException>(() => tokens.ReadRefresh(pair.AccessToken));
        Assert.Throws<ApiException>(() => MakeTokens('b').ReadRefresh(pair.RefreshToken));
        Assert.Throws<ApiException>(() => tokens.ReadRefresh("not-a-token"));
        Assert.NotEqual(pair.RefreshToken, tokens.Issue(session).RefreshToken);
    }

    [Fact]
    public void ExpiredJwtIsRejected()
    {
        var clock = new FixedTimeProvider(DateTimeOffset.UtcNow.AddHours(-2));
        var tokens = new Tokens(Options.Create(new AuthOptions { SigningKey = new string('a', 64) }), clock);
        var expired = tokens.Issue(new LoginSession { UserId = Guid.NewGuid(), ExpiresAt = DateTimeOffset.UtcNow.AddHours(-1) });
        Assert.Throws<ApiException>(() => tokens.ReadRefresh(expired.RefreshToken));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static Tokens MakeTokens(char key) => new(Options.Create(new AuthOptions
    {
        SigningKey = new string(key, 64),
        CodeKey = new string('c', 64)
    }), TimeProvider.System);
}
