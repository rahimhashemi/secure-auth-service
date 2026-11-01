package com.simpath.app.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

@Service
public class RateLimitService {
    // One atomic operation: accepted requests consume capacity; rejection never extends the window.
    private static final DefaultRedisScript<Long> SCRIPT = new DefaultRedisScript<>("""
            local count = tonumber(redis.call('GET', KEYS[1]) or '0')
            local ttl = redis.call('PTTL', KEYS[1])
            if count >= tonumber(ARGV[1]) then
                if ttl < 0 then
                    redis.call('PEXPIRE', KEYS[1], ARGV[2])
                    ttl = tonumber(ARGV[2])
                end
                return math.max(ttl, 1)
            end
            redis.call('INCR', KEYS[1])
            if ttl < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
            return 0
            """, Long.class);

    private final StringRedisTemplate redis;
    private final boolean enabled;
    private final int loginLimit;
    private final int refreshLimit;
    private final long windowMillis;

    public RateLimitService(StringRedisTemplate redis,
                            @Value("${app.rate-limit.enabled:true}") boolean enabled,
                            @Value("${app.rate-limit.login-limit:10}") int loginLimit,
                            @Value("${app.rate-limit.refresh-limit:30}") int refreshLimit,
                            @Value("${app.rate-limit.window-seconds:60}") long windowSeconds) {
        if (loginLimit < 1 || refreshLimit < 1 || windowSeconds < 1 || windowSeconds > 86400) {
            throw new IllegalArgumentException("Rate limits must be positive; window must be 1..86400 seconds.");
        }
        this.redis = redis;
        this.enabled = enabled;
        this.loginLimit = loginLimit;
        this.refreshLimit = refreshLimit;
        this.windowMillis = windowSeconds * 1000;
    }

    /** Returns zero when allowed, otherwise Retry-After in whole seconds. */
    public long check(String operation, String remoteAddress) {
        if (!enabled) return 0;
        int limit = switch (operation) {
            case "login" -> loginLimit;
            case "refresh" -> refreshLimit;
            default -> throw new IllegalArgumentException("Unsupported rate limit operation.");
        };
        String key = "secure-auth:rate-limit:v1:" + operation + ":" + hash(remoteAddress);
        Long retryMillis = redis.execute(SCRIPT, List.of(key), Integer.toString(limit), Long.toString(windowMillis));
        if (retryMillis == null || retryMillis < 0) {
            throw new DataAccessResourceFailureException("Rate limit decision unavailable.");
        }
        return (retryMillis + 999) / 1000;
    }

    private String hash(String remoteAddress) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(remoteAddress.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }
}
