using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AuthService.Features;
using AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Tests;

[Trait("Category", "Integration")]
public sealed class ApiTests(ApiFixture fixture) : IClassFixture<ApiFixture>
{
    private static int phoneSuffix = 100;
    private const string Password = "Test-password-123!";

    [Theory]
    [InlineData("email")]
    [InlineData("phone")]
    public async Task CompleteFlow(string type)
    {
        using var client = fixture.CreateClient();
        var (credentials, profile, pair) = await RegisterAndLogin(client, type);
        Assert.True(profile.IsActive);
        Assert.False(profile.IsContactVerified);
        Authorize(client, pair);
        var initial = await client.GetFromJsonAsync<UserProfile>("/users/me");
        Assert.False(initial!.IsContactVerified);

        var contact = await RequestCode(client, "/users/me/contact-verification/request", new { });
        Assert.Equal(type, fixture.Sender.Channels[contact.ChallengeId]);
        var confirmed = await client.PostAsJsonAsync("/users/me/contact-verification/confirm", Code(contact));
        Assert.Equal(HttpStatusCode.OK, confirmed.StatusCode);
        Assert.True((await confirmed.Content.ReadFromJsonAsync<UserProfile>())!.IsContactVerified);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/users/me/contact-verification/confirm", Code(contact))).StatusCode);

        var setup = await RequestCode(client, "/users/me/2fa/request", new FactorRequest("enable", Password));
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync("/users/me/2fa/enable", Code(setup))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/users/me")).StatusCode);
        client.DefaultRequestHeaders.Authorization = null;
        var loginResponse = await client.PostAsJsonAsync("/auth/login", credentials);
        var json = await loginResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(json.TryGetProperty("accessToken", out _));
        var challenge = json.Deserialize<ChallengeResponse>(new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        Assert.True(challenge.TwoFactorRequired);
        var verified = await client.PostAsJsonAsync("/auth/2fa/verify", Code(challenge));
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        pair = (await verified.Content.ReadFromJsonAsync<TokenPair>())!;
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/auth/2fa/verify", Code(challenge))).StatusCode);
        Authorize(client, pair);
        var disable = await RequestCode(client, "/users/me/2fa/request", new FactorRequest("disable", Password));
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync("/users/me/2fa/disable", Code(disable))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/users/me")).StatusCode);
        pair = await Login(client, credentials);
        var refreshed = await client.PostAsJsonAsync("/auth/refresh", new RefreshRequest(pair.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var next = (await refreshed.Content.ReadFromJsonAsync<TokenPair>())!;
        Assert.NotEqual(pair.RefreshToken, next.RefreshToken);
        Authorize(client, next);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/auth/logout", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/users/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/auth/refresh", new RefreshRequest(next.RefreshToken))).StatusCode);
    }

    [Fact]
    public async Task DuplicateRegistrationIsAtomic()
    {
        using var client = fixture.CreateClient();
        var credentials = NewCredentials("email");
        var results = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => client.PostAsJsonAsync("/auth/register", credentials)));
        Assert.Single(results, r => r.StatusCode == HttpStatusCode.Created);
        Assert.Single(results, r => r.StatusCode == HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task PasswordsAreHashedAndUnknownAccountsHaveSameError()
    {
        using var client = fixture.CreateClient();
        var (credentials, profile, _) = await RegisterAndLogin(client);
        using var scope = fixture.Services.CreateScope();
        var user = await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Users.FindAsync(profile.Id);
        Assert.NotEqual(Password, user!.PasswordHash);
        var wrong = await client.PostAsJsonAsync("/auth/login", credentials with { Password = "wrong-password" });
        var unknown = await client.PostAsJsonAsync("/auth/login", NewCredentials("email"));
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(await wrong.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task OldRefreshRevokesOnlyItsSession()
    {
        using var client = fixture.CreateClient();
        var (credentials, _, pair) = await RegisterAndLogin(client);
        var other = await Login(client, credentials);
        var next = await (await client.PostAsJsonAsync("/auth/refresh", new RefreshRequest(pair.RefreshToken)))
            .Content.ReadFromJsonAsync<TokenPair>();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/auth/refresh", new RefreshRequest(pair.RefreshToken))).StatusCode);
        Authorize(client, next!);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/users/me")).StatusCode);
        Authorize(client, other);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/users/me")).StatusCode);
    }

    [Fact]
    public async Task ConcurrentRefreshHasOneWinner()
    {
        using var client = fixture.CreateClient();
        var (_, _, pair) = await RegisterAndLogin(client);
        var results = await Task.WhenAll(Enumerable.Range(0, 2)
            .Select(_ => client.PostAsJsonAsync("/auth/refresh", new RefreshRequest(pair.RefreshToken))));
        Assert.Single(results, r => r.StatusCode == HttpStatusCode.OK);
        Assert.Single(results, r => r.StatusCode == HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ConcurrentRefreshAndLogoutCannotLeaveAnActiveSession()
    {
        using var client = fixture.CreateClient();
        var (_, _, pair) = await RegisterAndLogin(client);
        Authorize(client, pair);
        var results = await Task.WhenAll(client.PostAsJsonAsync("/auth/refresh", new RefreshRequest(pair.RefreshToken)),
            client.PostAsync("/auth/logout", null));
        Assert.Equal(HttpStatusCode.NoContent, results[1].StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/users/me")).StatusCode);
        if (results[0].IsSuccessStatusCode)
        {
            var next = (await results[0].Content.ReadFromJsonAsync<TokenPair>())!;
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/auth/refresh", new RefreshRequest(next.RefreshToken))).StatusCode);
        }
    }

    [Fact]
    public async Task CodesExpireAndHaveAnAttemptLimit()
    {
        using var client = fixture.CreateClient();
        var (_, user, pair) = await RegisterAndLogin(client);
        Authorize(client, pair);
        var challenge = await RequestCode(client, "/users/me/contact-verification/request", new { });
        var correct = Code(challenge);
        var wrong = correct with { Code = correct.Code == "000000" ? "111111" : "000000" };
        for (var i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/users/me/contact-verification/confirm", wrong)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/users/me/contact-verification/confirm", correct)).StatusCode);
        await fixture.Redis.GetDatabase().KeyDeleteAsync($"cooldown:{user.Id}:contact");
        challenge = await RequestCode(client, "/users/me/contact-verification/request", new { });
        await fixture.Redis.GetDatabase().KeyExpireAsync($"challenge:{challenge.ChallengeId}", TimeSpan.Zero);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/users/me/contact-verification/confirm", Code(challenge))).StatusCode);
    }

    [Fact]
    public async Task CodesCannotCrossUsersOrPurposesAndResendInvalidatesOldCode()
    {
        using var client = fixture.CreateClient();
        var (_, user, pair) = await RegisterAndLogin(client);
        Authorize(client, pair);
        var challenge = await RequestCode(client, "/users/me/contact-verification/request", new { });
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.PostAsJsonAsync("/users/me/contact-verification/request", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/auth/2fa/verify", Code(challenge))).StatusCode);
        using var other = fixture.CreateClient();
        var (_, _, otherPair) = await RegisterAndLogin(other);
        Authorize(other, otherPair);
        Assert.Equal(HttpStatusCode.BadRequest, (await other.PostAsJsonAsync("/users/me/contact-verification/confirm", Code(challenge))).StatusCode);
        await fixture.Redis.GetDatabase().KeyDeleteAsync($"cooldown:{user.Id}:contact");
        var replacement = await RequestCode(client, "/users/me/contact-verification/request", new { });
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/users/me/contact-verification/confirm", Code(challenge))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/users/me/contact-verification/confirm", Code(replacement))).StatusCode);
    }

    [Fact]
    public async Task ConcurrentSecondFactorCreatesOneSession()
    {
        using var client = fixture.CreateClient();
        var (credentials, _, pair) = await RegisterAndLogin(client);
        Authorize(client, pair);
        var setup = await RequestCode(client, "/users/me/2fa/request", new FactorRequest("enable", Password));
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync("/users/me/2fa/enable", Code(setup))).StatusCode);
        var login = await (await client.PostAsJsonAsync("/auth/login", credentials)).Content.ReadFromJsonAsync<ChallengeResponse>();
        var responses = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => client.PostAsJsonAsync("/auth/2fa/verify", Code(login!))));
        Assert.Single(responses, r => r.StatusCode == HttpStatusCode.OK);
        Assert.Single(responses, r => r.StatusCode == HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task TokenTypesAndExpiredSessionsAreRejected()
    {
        using var client = fixture.CreateClient();
        var (_, user, pair) = await RegisterAndLogin(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pair.RefreshToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/users/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/auth/refresh", new RefreshRequest(pair.AccessToken))).StatusCode);
        using var scope = fixture.Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Sessions.Where(s => s.UserId == user.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, DateTimeOffset.UtcNow.AddMinutes(-1)));
        Authorize(client, pair);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/users/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/auth/refresh", new RefreshRequest(pair.RefreshToken))).StatusCode);
    }

    private async Task<(Credentials, UserProfile, TokenPair)> RegisterAndLogin(HttpClient client, string type = "email")
    {
        var credentials = NewCredentials(type);
        var response = await client.PostAsJsonAsync("/auth/register", credentials);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var profile = (await response.Content.ReadFromJsonAsync<UserProfile>())!;
        return (credentials, profile, await Login(client, credentials));
    }

    private static Credentials NewCredentials(string type) => new(type,
        type == "email" ? $"{Guid.NewGuid():N}@example.com" : $"+1202555{Interlocked.Increment(ref phoneSuffix):D4}", Password);
    private static void Authorize(HttpClient client, TokenPair pair) =>
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pair.AccessToken);
    private CodeRequest Code(ChallengeResponse challenge) => new(challenge.ChallengeId, fixture.Sender.Codes[challenge.ChallengeId]);
    private static async Task<TokenPair> Login(HttpClient client, Credentials credentials)
    {
        var response = await client.PostAsJsonAsync("/auth/login", credentials);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<TokenPair>())!;
    }
    private static async Task<ChallengeResponse> RequestCode(HttpClient client, string path, object body)
    {
        var response = await client.PostAsJsonAsync(path, body);
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<ChallengeResponse>())!;
    }
}
