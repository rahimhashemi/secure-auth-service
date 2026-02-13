package com.simpath.app.auth.dto;

public record AuthResponse(String accessToken, long accessExpiresInSeconds, String refreshToken,
                           long refreshExpiresInSeconds) {
}
