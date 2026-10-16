namespace AuthService.Configuration;

public sealed class AuthOptions
{
    public string SigningKey { get; set; } = "";
    public string CodeKey { get; set; } = "";
    public string Issuer { get; set; } = "auth-service";
    public string Audience { get; set; } = "auth-service-client";
    public string RedisKeyPrefix { get; set; } = "auth:";
    public int AccessMinutes { get; set; } = 15;
    public int SessionDays { get; set; } = 7;
    public int ContactCodeMinutes { get; set; } = 10;
    public int FactorCodeMinutes { get; set; } = 5;
    public int CodeAttempts { get; set; } = 5;
    public int SendCooldownSeconds { get; set; } = 60;
}
