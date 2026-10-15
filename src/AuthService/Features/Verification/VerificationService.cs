using AuthService.Features.Auth;
using AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Features.Verification;

public sealed class VerificationService(AuthDbContext db, AccountService accounts, SessionService sessions,
    ChallengeStore codes, TimeProvider clock)
{
    public async Task<ChallengeResponse> RequestContact(Guid userId, Guid sessionId, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var user = await LockAuthorized(userId, sessionId, ct);
        if (user.ContactVerifiedAt.HasValue) throw ApiException.Conflict("Contact is already verified.");
        var result = await codes.Issue(user, "contact");
        await tx.CommitAsync(ct);
        return result;
    }

    public async Task<UserProfile> ConfirmContact(Guid userId, Guid sessionId, CodeRequest request, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var user = await LockAuthorized(userId, sessionId, ct);
        var challenge = await codes.Peek(request.ChallengeId, "contact", userId);
        await codes.Consume(request.ChallengeId, request.Code, challenge);
        user.ContactVerifiedAt ??= clock.GetUtcNow();
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return UserProfile.From(user);
    }

    public async Task<ChallengeResponse> RequestFactor(Guid userId, Guid sessionId, FactorRequest request, CancellationToken ct)
    {
        await codes.Limit("factor-password:" + userId, 10, 300);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var user = await LockAuthorized(userId, sessionId, ct);
        accounts.CheckPassword(user, request.Password);
        if (user.TwoFactorEnabled == (request.Action == "enable"))
            throw ApiException.Conflict("Two-factor authentication is already in the requested state.");
        var result = await codes.Issue(user, request.Action);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return result;
    }

    public async Task ChangeFactor(Guid userId, Guid sessionId, string action, CodeRequest request, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var user = await LockAuthorized(userId, sessionId, ct);
        var challenge = await codes.Peek(request.ChallengeId, action, userId);
        if (challenge.SecurityVersion != user.SecurityVersion) throw ApiException.InvalidCode();
        if (user.TwoFactorEnabled == (action == "enable")) throw ApiException.Conflict("State already changed.");
        await codes.Consume(request.ChallengeId, request.Code, challenge);
        user.TwoFactorEnabled = action == "enable";
        user.SecurityVersion++;
        if (user.TwoFactorEnabled) user.ContactVerifiedAt ??= clock.GetUtcNow();
        await db.Sessions.Where(x => x.UserId == userId && x.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, clock.GetUtcNow()), ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    public async Task<TokenPair> VerifyLogin(CodeRequest request, string ip, CancellationToken ct)
    {
        await codes.Limit("verify-ip:" + codes.RateKey(ip), 100, 300);
        var challenge = await codes.Peek(request.ChallengeId, "login");
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var user = await db.LockUser(challenge.UserId, ct) ?? throw ApiException.InvalidCode();
        if (!user.IsActive || !user.TwoFactorEnabled || user.SecurityVersion != challenge.SecurityVersion)
            throw ApiException.InvalidCode();
        await codes.Consume(request.ChallengeId, request.Code, challenge);
        var pair = sessions.Create(user.Id);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return pair;
    }

    private async Task<User> LockAuthorized(Guid userId, Guid sessionId, CancellationToken ct)
    {
        var user = await db.LockUser(userId, ct) ?? throw ApiException.Unauthorized();
        if (!user.IsActive) throw ApiException.Unauthorized();
        // Recheck after locking: middleware may have run before logout.
        sessions.EnsureValid(await db.Sessions.AsNoTracking().SingleOrDefaultAsync(x => x.Id == sessionId, ct), userId);
        return user;
    }
}
