using Npgsql;
using StackExchange.Redis;

namespace AuthService.Infrastructure;

public static class StorageErrors
{
    public static bool IsUnavailable(Exception error)
    {
        // EF may wrap a connection failure in another exception.
        for (Exception? current = error; current is not null; current = current.InnerException)
        {
            if (current is RedisException or NpgsqlException) return true;
        }
        return false;
    }
}
