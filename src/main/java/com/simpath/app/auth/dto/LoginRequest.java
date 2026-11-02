package com.simpath.app.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @Email @NotBlank @jakarta.validation.constraints.Size(max = 190) String email,
        @NotBlank @jakarta.validation.constraints.Size(max = 72) String password
) {
}

