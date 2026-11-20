package com.simpath.app.auth.dto;

public record AuthResponse(String accessToken, long accessExpiresInSeconds, String refreshToken,
                           long refreshExpiresInSeconds, boolean mfaRequired, String mfaChallengeToken) {
    public AuthResponse(String accessToken, long accessExpiresInSeconds, String refreshToken,
                        long refreshExpiresInSeconds) {
        this(accessToken, accessExpiresInSeconds, refreshToken, refreshExpiresInSeconds, false, null);
    }

    public static AuthResponse mfaRequired(String challenge) {
        return new AuthResponse(null, 0, null, 0, true, challenge);
    }
}
