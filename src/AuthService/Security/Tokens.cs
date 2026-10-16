using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthService.Configuration;
using AuthService.Features;
using AuthService.Infrastructure;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Security;

public sealed class Tokens(IOptions<AuthOptions> options, TimeProvider clock)
{
    private readonly AuthOptions settings = options.Value;
    public TokenValidationParameters Validation(string type) => new()
    {
        ValidateIssuer = true,
        ValidIssuer = settings.Issuer,
        ValidateAudience = true,
        ValidAudience = settings.Audience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(settings.SigningKey)),
        ValidateLifetime = true,
        RequireExpirationTime = true,
        RequireSignedTokens = true,
        ClockSkew = TimeSpan.Zero,
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        ValidTypes = [type]
    };

    public TokenPair Issue(LoginSession session)
    {
        var now = clock.GetUtcNow();
        var accessEnd = now.AddMinutes(settings.AccessMinutes);
        if (accessEnd > session.ExpiresAt) accessEnd = session.ExpiresAt;
        return new(Create(session, "access", accessEnd), Create(session, "refresh", session.ExpiresAt),
            Math.Max(0, (int)(accessEnd - now).TotalSeconds));
    }

    private string Create(LoginSession session, string type, DateTimeOffset expires)
    {
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(settings.SigningKey)), SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(settings.Issuer, settings.Audience,
        [
            new Claim("sub", session.UserId.ToString()), new Claim("sid", session.Id.ToString()),
            new Claim("jti", Guid.NewGuid().ToString()), new Claim("token_use", type),
            new Claim("iat", clock.GetUtcNow().ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        ], clock.GetUtcNow().UtcDateTime, expires.UtcDateTime, credentials);
        token.Header["typ"] = type;
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public (Guid UserId, Guid SessionId) ReadRefresh(string token)
    {
        try
        {
            var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }
                .ValidateToken(token, Validation("refresh"), out _);
            if (!HasRequiredClaims(principal, "refresh")) throw ApiException.Unauthorized();
            return (Guid.Parse(principal.FindFirstValue("sub")!), Guid.Parse(principal.FindFirstValue("sid")!));
        }
        catch (Exception e) when (e is SecurityTokenException or ArgumentException or FormatException)
        {
            throw ApiException.Unauthorized();
        }
    }

    public static string Digest(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    public static bool HasRequiredClaims(ClaimsPrincipal principal, string type) =>
        principal.FindFirstValue("token_use") == type
        && Guid.TryParse(principal.FindFirstValue("sub"), out _)
        && Guid.TryParse(principal.FindFirstValue("sid"), out _)
        && Guid.TryParse(principal.FindFirstValue("jti"), out _)
        && long.TryParse(principal.FindFirstValue("iat"), out _);

    public static bool SameDigest(string left, string right) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));
}
