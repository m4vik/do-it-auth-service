using System.Security.Claims;
using AuthService.Features.Auth;
using AuthService.Features.Verification;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Features;

[ApiController]
[Authorize]
[Route("users/me")]
public sealed class UsersController(AccountService accounts, VerificationService verification) : ControllerBase
{
    private Guid UserId => Guid.Parse(User.FindFirstValue("sub")!);
    private Guid SessionId => Guid.Parse(User.FindFirstValue("sid")!);

    [HttpGet]
    public async Task<UserProfile> Me(CancellationToken ct) => UserProfile.From(await accounts.Get(UserId, ct));

    [HttpPost("contact-verification/request")]
    public async Task<IActionResult> RequestContact(CancellationToken ct) =>
        Accepted(await verification.RequestContact(UserId, SessionId, ct));

    [HttpPost("contact-verification/confirm")]
    public Task<UserProfile> ConfirmContact(CodeRequest request, CancellationToken ct) =>
        verification.ConfirmContact(UserId, SessionId, request, ct);

    [HttpPost("2fa/request")]
    public async Task<IActionResult> RequestFactor(FactorRequest request, CancellationToken ct) =>
        Accepted(await verification.RequestFactor(UserId, SessionId, request, ct));

    [HttpPost("2fa/enable")]
    public async Task<IActionResult> Enable(CodeRequest request, CancellationToken ct)
    {
        await verification.ChangeFactor(UserId, SessionId, "enable", request, ct);
        return NoContent();
    }

    [HttpPost("2fa/disable")]
    public async Task<IActionResult> Disable(CodeRequest request, CancellationToken ct)
    {
        await verification.ChangeFactor(UserId, SessionId, "disable", request, ct);
        return NoContent();
    }
}
