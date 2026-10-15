using AuthService.Infrastructure;
using AuthService.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace AuthService.Features.Auth;

public sealed class AccountService(AuthDbContext db, IPasswordHasher<User> passwords)
{
    public async Task<UserProfile> Register(Credentials request, CancellationToken ct)
    {
        var (type, value) = Identifiers.Normalize(request.IdentifierType, request.Identifier);
        var user = new User { IdentifierType = type, Identifier = value };
        user.PasswordHash = passwords.HashPassword(user, request.Password);
        db.Users.Add(user);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException e) when (e.InnerException is PostgresException { SqlState: "23505" })
        {
            throw ApiException.Conflict("An account with this contact already exists.");
        }
        return UserProfile.From(user);
    }

    public async Task<User> Get(Guid id, CancellationToken ct) =>
        await db.Users.SingleOrDefaultAsync(x => x.Id == id && x.IsActive, ct) ?? throw ApiException.Unauthorized();

    public void CheckPassword(User user, string password)
    {
        var result = passwords.VerifyHashedPassword(user, user.PasswordHash, password);
        if (result == PasswordVerificationResult.Failed) throw ApiException.Unauthorized();
        if (result == PasswordVerificationResult.SuccessRehashNeeded)
            user.PasswordHash = passwords.HashPassword(user, password);
    }
}
