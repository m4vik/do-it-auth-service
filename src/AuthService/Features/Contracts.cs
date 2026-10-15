using System.ComponentModel.DataAnnotations;
using AuthService.Infrastructure;

namespace AuthService.Features;

public sealed record Credentials(
    [Required, StringLength(10)] string IdentifierType,
    [Required, StringLength(254)] string Identifier,
    [Required, StringLength(128, MinimumLength = 8)] string Password);
public sealed record RefreshRequest([Required, StringLength(4096)] string RefreshToken);
public sealed record CodeRequest(
    Guid ChallengeId,
    [Required, RegularExpression("^[0-9]{6}$")] string Code);
public sealed record FactorRequest(
    [Required, RegularExpression("^(enable|disable)$")] string Action,
    [Required, StringLength(128, MinimumLength = 8)] string Password);
public sealed record ChallengeResponse(Guid ChallengeId, int ExpiresIn, bool TwoFactorRequired = false);
public sealed record TokenPair(string AccessToken, string RefreshToken, int ExpiresIn, string TokenType = "Bearer");
public sealed record UserProfile(Guid Id, string IdentifierType, string Identifier, bool IsActive,
    bool IsContactVerified, bool TwoFactorEnabled)
{
    public static UserProfile From(User user) => new(user.Id, user.IdentifierType, user.Identifier,
        user.IsActive, user.ContactVerifiedAt.HasValue, user.TwoFactorEnabled);
}
