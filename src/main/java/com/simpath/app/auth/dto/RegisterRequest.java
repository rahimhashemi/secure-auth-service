package com.simpath.app.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record RegisterRequest(
        @Email @NotBlank @jakarta.validation.constraints.Size(max = 190) String email,
        @com.simpath.app.security.RegistrationPassword String password
) {
}


