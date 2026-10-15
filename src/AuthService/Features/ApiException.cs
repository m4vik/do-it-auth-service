namespace AuthService.Features;

public sealed class ApiException(int status, string code, string message) : Exception(message)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
    public static ApiException Unauthorized() => new(401, "unauthorized", "Invalid credentials or expired session.");
    public static ApiException InvalidCode() => new(400, "invalid_code", "Invalid, expired or already used code.");
    public static ApiException Conflict(string message) => new(409, "conflict", message);
    public static ApiException Limited() => new(429, "rate_limited", "Too many attempts. Try again later.");
}
