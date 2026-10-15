namespace AuthService.Features.Verification;

public interface ICodeSender
{
    Task Send(string channel, string recipient, string purpose, Guid challengeId, string code);
}

public sealed class LogCodeSender(ILogger<LogCodeSender> logger) : ICodeSender
{
    public Task Send(string channel, string recipient, string purpose, Guid challengeId, string code)
    {
        // Demo delivery only, explicitly allowed by the assignment.
        logger.LogInformation("DEMO {Channel} to {Recipient}: purpose={Purpose} challenge={ChallengeId} code={Code}",
            channel == "phone" ? "SMS" : "EMAIL", recipient, purpose, challengeId, code);
        return Task.CompletedTask;
    }
}
