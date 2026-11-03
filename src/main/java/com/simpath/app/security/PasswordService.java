package com.simpath.app.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Component
public class PasswordService {
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    private final String dummyHash = encoder.encode(UUID.randomUUID().toString());

    public String hash(String raw) { return encoder.encode(raw); }

    // A missing user still performs a cost-12 BCrypt comparison. Oversized input
    // is rejected after dummy work, never silently truncated by BCrypt.
    public boolean matches(String raw, String hash) {
        boolean oversized = raw == null || raw.getBytes(StandardCharsets.UTF_8).length > 72;
        String candidate = oversized ? "invalid-input" : raw;
        boolean matched = encoder.matches(candidate, hash == null || oversized ? dummyHash : hash);
        return !oversized && hash != null && matched;
    }
}
