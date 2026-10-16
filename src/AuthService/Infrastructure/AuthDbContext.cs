using Microsoft.EntityFrameworkCore;

namespace AuthService.Infrastructure;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<LoginSession> Sessions => Set<LoginSession>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        var user = model.Entity<User>();
        user.ToTable("users", table => table.HasCheckConstraint("CK_users_type", "\"IdentifierType\" IN ('email', 'phone')"));
        user.HasKey(x => x.Id);
        user.Property(x => x.IdentifierType).HasMaxLength(10);
        user.Property(x => x.Identifier).HasMaxLength(254);
        user.Property(x => x.PasswordHash).HasMaxLength(512);
        user.HasIndex(x => new { x.IdentifierType, x.Identifier }).IsUnique();

        var session = model.Entity<LoginSession>();
        session.ToTable("sessions");
        session.HasKey(x => x.Id);
        session.Property(x => x.RefreshDigest).HasMaxLength(64);
        session.HasOne<User>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        session.HasIndex(x => x.UserId);
    }

    public Task<User?> LockUser(Guid id, CancellationToken ct) =>
        Users.FromSqlInterpolated($"SELECT * FROM users WHERE \"Id\" = {id} FOR UPDATE")
            .SingleOrDefaultAsync(ct);

    public Task<LoginSession?> LockSession(Guid id, CancellationToken ct) =>
        Sessions.FromSqlInterpolated($"SELECT * FROM sessions WHERE \"Id\" = {id} FOR UPDATE")
            .SingleOrDefaultAsync(ct);
}
