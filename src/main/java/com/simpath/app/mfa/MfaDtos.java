package com.simpath.app.mfa;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import java.util.List;

public final class MfaDtos {
    private MfaDtos() { }

    @Getter @Setter
    public static class PasswordRequest {
        @NotBlank @Size(max = 72)
        private String password;
    }

    @Getter @Setter
    public static class CodeRequest {
        @NotBlank @Size(max = 64)
        private String code;
    }

    @Getter @Setter
    public static class PasswordCodeRequest {
        @NotBlank @Size(max = 72)
        private String password;
        @NotBlank @Size(max = 64)
        private String code;
    }

    @Getter @Setter
    public static class VerifyRequest {
        @NotBlank @Size(max = 128)
        private String challengeToken;
        @NotBlank @Size(max = 64)
        private String code;
    }

    @Getter @RequiredArgsConstructor
    public static class StatusResponse {
        private final boolean enabled;
        private final boolean pending;
    }

    @Getter @RequiredArgsConstructor
    public static class SetupResponse {
        private final String secret;
        private final String provisioningUri;
    }

    @Getter @RequiredArgsConstructor
    public static class RecoveryResponse {
        private final List<String> recoveryCodes;
    }
}
