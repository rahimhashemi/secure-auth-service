package com.simpath.app.user;

import com.simpath.app.token.token.AuthPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class MeController {

    @GetMapping("/me")
    public Map<String, Object> me(Authentication authentication) {
        var principal = (AuthPrincipal) authentication.getPrincipal();
        return Map.of(
                "userId", principal.userId(),
                "email", principal.email()
        );
    }
}
