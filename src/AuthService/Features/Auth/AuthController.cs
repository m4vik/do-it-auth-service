using System.Security.Claims;
using AuthService.Features.Verification;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Features.Auth;

[ApiController]
[Route("auth")]
public sealed class AuthController(AccountService accounts, SessionService sessions, VerificationService verification) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register(Credentials request, CancellationToken ct) =>
        StatusCode(201, await accounts.Register(request, ct));

    [HttpPost("login")]
    public async Task<IActionResult> Login(Credentials request, CancellationToken ct) =>
        Ok(await sessions.Login(request, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", ct));

    [HttpPost("2fa/verify")]
    public async Task<IActionResult> Verify(CodeRequest request, CancellationToken ct) =>
        Ok(await verification.VerifyLogin(request, HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown", ct));

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(RefreshRequest request, CancellationToken ct) =>
        Ok(await sessions.Refresh(request.RefreshToken, ct));

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        await sessions.Logout(Guid.Parse(User.FindFirstValue("sub")!), Guid.Parse(User.FindFirstValue("sid")!), ct);
        return NoContent();
    }
}
