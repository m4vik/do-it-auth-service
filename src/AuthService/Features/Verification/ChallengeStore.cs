using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthService.Configuration;
using AuthService.Infrastructure;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace AuthService.Features.Verification;

public sealed record Challenge(Guid UserId, string Purpose, int SecurityVersion);

public sealed class ChallengeStore(IConnectionMultiplexer redis, IOptions<AuthOptions> options, ICodeSender sender)
{
    private readonly IDatabase db = redis.GetDatabase();
    private readonly AuthOptions settings = options.Value;

    public async Task Limit(string key, int limit, int seconds)
    {
        const string script = """
            local n = redis.call('INCR', KEYS[1])
            if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
            return n
            """;
        var count = (long)await db.ScriptEvaluateAsync(script, [Key("limit:" + key)], [seconds]);
        if (count > limit) throw ApiException.Limited();
    }

    public async Task<ChallengeResponse> Issue(User user, string purpose)
    {
        var id = Guid.NewGuid();
        var code = RandomNumberGenerator.GetInt32(1_000_000).ToString("D6");
        var seconds = 60 * (purpose == "contact" ? settings.ContactCodeMinutes : settings.FactorCodeMinutes);
        var data = JsonSerializer.Serialize(new Challenge(user.Id, purpose, user.SecurityVersion));
        const string script = """
            if not redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1]) then return 0 end
            local old = redis.call('GET', KEYS[2])
            if old then redis.call('DEL', old) end
            redis.call('HSET', KEYS[3], 'data', ARGV[3], 'digest', ARGV[4], 'attempts', 0)
            redis.call('EXPIRE', KEYS[3], ARGV[2])
            redis.call('SET', KEYS[2], KEYS[3], 'EX', ARGV[2])
            return 1
            """;
        var issued = (long)await db.ScriptEvaluateAsync(script,
            [Key($"cooldown:{user.Id}:{purpose}"), Key($"current:{user.Id}:{purpose}"), Key($"challenge:{id}")],
            [settings.SendCooldownSeconds, seconds, data, Hash(id, code)]);
        if (issued == 0) throw ApiException.Limited();
        await sender.Send(user.IdentifierType, user.Identifier, purpose, id, code);
        return new(id, seconds, purpose == "login");
    }

    public async Task<Challenge> Peek(Guid id, string purpose, Guid? userId = null)
    {
        var raw = await db.HashGetAsync(Key($"challenge:{id}"), "data");
        if (raw.IsNullOrEmpty) throw ApiException.InvalidCode();
        var value = JsonSerializer.Deserialize<Challenge>((string)raw!)!;
        if (value.Purpose != purpose || (userId.HasValue && value.UserId != userId)) throw ApiException.InvalidCode();
        return value;
    }

    public async Task Consume(Guid id, string code, Challenge expected)
    {
        // Verification and deletion are a single atomic Redis operation.
        const string script = """
            if redis.call('HGET', KEYS[1], 'data') ~= ARGV[1] then return 0 end
            local tries = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
            if redis.call('HGET', KEYS[1], 'digest') == ARGV[2] then
                redis.call('DEL', KEYS[1]); return 1
            end
            if tries >= tonumber(ARGV[3]) then redis.call('DEL', KEYS[1]) end
            return 0
            """;
        var result = (long)await db.ScriptEvaluateAsync(script, [Key($"challenge:{id}")],
            [JsonSerializer.Serialize(expected), Hash(id, code), settings.CodeAttempts]);
        if (result != 1) throw ApiException.InvalidCode();
    }

    public string RateKey(string value) => Convert.ToHexString(
        HMACSHA256.HashData(Encoding.UTF8.GetBytes(settings.CodeKey), Encoding.UTF8.GetBytes(value)));
    private string Hash(Guid id, string code) => RateKey($"{id}:{code}");
    private string Key(string key) => settings.RedisKeyPrefix + key;
}
