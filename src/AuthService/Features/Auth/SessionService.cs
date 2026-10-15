using AuthService.Configuration;
using AuthService.Features.Verification;
using AuthService.Infrastructure;
using AuthService.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthService.Features.Auth;

public sealed class SessionService(AuthDbContext db, AccountService accounts, Tokens tokens,
    ChallengeStore codes, IOptions<AuthOptions> options, TimeProvider clock, IPasswordHasher<User> passwords)
{
    // Spend password-hashing work for unknown accounts too.
    private static readonly User Dummy = new();
    private static readonly string DummyHash = new PasswordHasher<User>().HashPassword(Dummy, "unused-dummy-password");

    public async Task<object> Login(Credentials request, string ip, CancellationToken ct)
    {
        await codes.Limit("login-ip:" + codes.RateKey(ip), 100, 300);
        var (type, identifier) = Identifiers.Normalize(request.IdentifierType, request.Identifier);
        await codes.Limit("login-user:" + codes.RateKey(type + identifier), 10, 300);
        var id = await db.Users.Where(x => x.IdentifierType == type && x.Identifier == identifier)
            .Select(x => (Guid?)x.Id).SingleOrDefaultAsync(ct);
        if (id is null)
        {
            passwords.VerifyHashedPassword(Dummy, DummyHash, request.Password);
            throw ApiException.Unauthorized();
        }
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var user = await db.LockUser(id.Value, ct) ?? throw ApiException.Unauthorized();
        if (!user.IsActive) throw ApiException.Unauthorized();
        accounts.CheckPassword(user, request.Password);
        object response = user.TwoFactorEnabled ? await codes.Issue(user, "login") : Create(user.Id);
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
        return response;
    }

    public TokenPair Create(Guid userId)
    {
        var session = new LoginSession { UserId = userId, ExpiresAt = clock.GetUtcNow().AddDays(options.Value.SessionDays) };
        var pair = tokens.Issue(session);
        session.RefreshDigest = Tokens.Digest(pair.RefreshToken);
        db.Sessions.Add(session);
        return pair;
    }

    public async Task<TokenPair> Refresh(string refresh, CancellationToken ct)
    {
        var (userId, sessionId) = tokens.ReadRefresh(refresh);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        // All auth mutations lock user before session to avoid lock inversions.
        var user = await db.LockUser(userId, ct) ?? throw ApiException.Unauthorized();
        var session = await db.LockSession(sessionId, ct);
        EnsureValid(session, userId);
        if (!user.IsActive) throw ApiException.Unauthorized();
        if (!Tokens.SameDigest(session!.RefreshDigest, Tokens.Digest(refresh)))
        {
            session.RevokedAt = clock.GetUtcNow();
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            throw ApiException.Unauthorized();
        }
        var pair = tokens.Issue(session);
        session.RefreshDigest = Tokens.Digest(pair.RefreshToken);
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
        return pair;
    }

    public async Task Logout(Guid userId, Guid sessionId, CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await db.LockUser(userId, ct);
        var session = await db.LockSession(sessionId, ct);
        EnsureValid(session, userId);
        session!.RevokedAt = clock.GetUtcNow();
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
    }

    public void EnsureValid(LoginSession? session, Guid userId)
    {
        if (session is null || session.UserId != userId || session.RevokedAt is not null || session.ExpiresAt <= clock.GetUtcNow())
            throw ApiException.Unauthorized();
    }
}
