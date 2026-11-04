package com.simpath.app.verification;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/auth/email-verification")
public class VerificationController {
    private final VerificationService verification;
    public VerificationController(VerificationService verification) { this.verification = verification; }
    @Getter @Setter
    public static class Request {
        @NotBlank @Email @Size(max = 190) private String email;
    }
    @Getter @Setter
    public static class Confirm {
        @NotBlank @Size(max = 128) private String token;
    }
    @PostMapping("/request") @ResponseStatus(org.springframework.http.HttpStatus.ACCEPTED)
    public java.util.Map<String, String> request(@Valid @RequestBody Request request) {
        verification.request(request.getEmail());
        return java.util.Map.of("message", "If the account needs verification, an email will be sent.");
    }
    @PostMapping("/confirm") @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void confirm(@Valid @RequestBody Confirm request) { verification.confirm(request.getToken()); }
}
