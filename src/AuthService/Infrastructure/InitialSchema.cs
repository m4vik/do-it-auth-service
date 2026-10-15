using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace AuthService.Infrastructure;

[DbContext(typeof(AuthDbContext))]
[Migration("202610150001_InitialSchema")]
public sealed class InitialSchema : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder) => migrationBuilder.Sql("""
        CREATE TABLE users (
            "Id" uuid PRIMARY KEY,
            "IdentifierType" varchar(10) NOT NULL,
            "Identifier" varchar(254) NOT NULL,
            "PasswordHash" varchar(512) NOT NULL,
            "IsActive" boolean NOT NULL,
            "ContactVerifiedAt" timestamptz NULL,
            "TwoFactorEnabled" boolean NOT NULL,
            "SecurityVersion" integer NOT NULL,
            "CreatedAt" timestamptz NOT NULL,
            CONSTRAINT "CK_users_type" CHECK ("IdentifierType" IN ('email', 'phone'))
        );
        CREATE UNIQUE INDEX "IX_users_IdentifierType_Identifier" ON users ("IdentifierType", "Identifier");
        CREATE TABLE sessions (
            "Id" uuid PRIMARY KEY,
            "UserId" uuid NOT NULL REFERENCES users ("Id") ON DELETE CASCADE,
            "RefreshDigest" varchar(64) NOT NULL,
            "ExpiresAt" timestamptz NOT NULL,
            "RevokedAt" timestamptz NULL,
            "CreatedAt" timestamptz NOT NULL
        );
        CREATE INDEX "IX_sessions_UserId" ON sessions ("UserId");
        """);

    protected override void Down(MigrationBuilder migrationBuilder) =>
        migrationBuilder.Sql("DROP TABLE sessions; DROP TABLE users;");
}
