namespace AuthService.Infrastructure;

public sealed class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string IdentifierType { get; set; } = "";
    public string Identifier { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public bool IsActive { get; set; } = true;
    public DateTimeOffset? ContactVerifiedAt { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public int SecurityVersion { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class LoginSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string RefreshDigest { get; set; } = "";
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
