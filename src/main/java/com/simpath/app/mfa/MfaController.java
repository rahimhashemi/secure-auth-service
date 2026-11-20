package com.simpath.app.mfa;

import com.simpath.app.auth.dto.AuthResponse;
import com.simpath.app.security.ClientAddressResolver;
import com.simpath.app.token.token.AuthPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController
@RequestMapping("/auth/mfa")
public class MfaController {
    private final MfaService mfa;
    private final ClientAddressResolver addresses;

    public MfaController(MfaService mfa, ClientAddressResolver addresses) {
        this.mfa = mfa;
        this.addresses = addresses;
    }

    @GetMapping("/status")
    public ResponseEntity<MfaDtos.StatusResponse> status(@AuthenticationPrincipal AuthPrincipal principal) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(mfa.status(UUID.fromString(principal.userId())));
    }

    @PostMapping("/totp/setup")
    public ResponseEntity<MfaDtos.SetupResponse> setup(@AuthenticationPrincipal AuthPrincipal principal,
            @Valid @RequestBody MfaDtos.PasswordRequest request, HttpServletRequest http) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(mfa.setup(UUID.fromString(principal.userId()), request.getPassword(),
                        addresses.resolve(http), http.getHeader("User-Agent")));
    }

    @PostMapping("/totp/confirm")
    public ResponseEntity<MfaDtos.RecoveryResponse> confirm(@AuthenticationPrincipal AuthPrincipal principal,
            @Valid @RequestBody MfaDtos.CodeRequest request, HttpServletRequest http) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(mfa.confirm(UUID.fromString(principal.userId()), request.getCode(),
                        addresses.resolve(http), http.getHeader("User-Agent")));
    }

    @PostMapping("/challenge/verify")
    public ResponseEntity<AuthResponse> verify(@Valid @RequestBody MfaDtos.VerifyRequest request, HttpServletRequest http) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(mfa.verifyChallenge(request.getChallengeToken(), request.getCode(),
                        http.getHeader("User-Agent"), addresses.resolve(http)));
    }

    @PostMapping("/recovery/regenerate")
    public ResponseEntity<MfaDtos.RecoveryResponse> regenerate(@AuthenticationPrincipal AuthPrincipal principal,
            @Valid @RequestBody MfaDtos.PasswordCodeRequest request, HttpServletRequest http) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(mfa.regenerate(UUID.fromString(principal.userId()), request.getPassword(), request.getCode(),
                        addresses.resolve(http), http.getHeader("User-Agent")));
    }

    @PostMapping("/disable")
    public ResponseEntity<Void> disable(@AuthenticationPrincipal AuthPrincipal principal,
            @Valid @RequestBody MfaDtos.PasswordCodeRequest request, HttpServletRequest http) {
        mfa.disable(UUID.fromString(principal.userId()), request.getPassword(), request.getCode(),
                addresses.resolve(http), http.getHeader("User-Agent"));
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }
}
