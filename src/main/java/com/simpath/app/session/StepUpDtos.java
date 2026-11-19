package com.simpath.app.session;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import java.time.Instant;

public final class StepUpDtos {
    private StepUpDtos() { }

    @Getter @Setter
    public static class Request {
        @NotBlank @Size(max = 72)
        private String password;

        // Required for an account with MFA enabled; optional for password-only accounts.
        @Size(max = 64)
        private String code;
    }

    @Getter @RequiredArgsConstructor
    public static class Response {
        private final Instant validUntil;
    }

    @Getter @RequiredArgsConstructor
    public static class StatusResponse {
        private final boolean elevated;
        private final Instant validUntil;
    }
}
