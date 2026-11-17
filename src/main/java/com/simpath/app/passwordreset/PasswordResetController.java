package com.simpath.app.passwordreset;

import com.simpath.app.security.RegistrationPassword;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth/password-reset")
public class PasswordResetController {
    private final PasswordResetService service;

    public PasswordResetController(PasswordResetService service) {
        this.service = service;
    }

    @Getter
    @Setter
    public static class Request {
        @NotBlank @Email @Size(max = 190) private String email;
    }

    @Getter
    @Setter
    public static class Confirm {
        @NotBlank @Size(max = 128) private String token;
        @RegistrationPassword private String newPassword;
    }

    @PostMapping("/request")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public Map<String, String> request(@Valid @RequestBody Request request) {
        service.request(request.getEmail());
        return Map.of("message", "If the account is eligible, a reset link will be sent.");
    }

    @PostMapping("/confirm")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void confirm(@Valid @RequestBody Confirm request) {
        service.confirm(request.getToken(), request.getNewPassword());
    }
}
