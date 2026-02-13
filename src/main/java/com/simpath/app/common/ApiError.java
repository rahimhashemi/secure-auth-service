package com.simpath.app.common;

import java.time.Instant;

public record ApiError(
        String code,
        String message,
        Instant timestamp,
        String path
) {
    public static ApiError of(String code, String message, String path) {
        return new ApiError(code, message, Instant.now(), path);
    }
}
