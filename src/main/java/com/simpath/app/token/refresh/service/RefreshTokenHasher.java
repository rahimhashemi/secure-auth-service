package com.simpath.app.token.refresh.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@Component
public class RefreshTokenHasher {

    private final String pepper;

    public RefreshTokenHasher(@Value("${app.refresh-token.pepper}") String pepper) {
        this.pepper = pepper;
    }

    public String hash(String refreshTokenPlain) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest((pepper + ":" + refreshTokenPlain).getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot hash refresh token", e);
        }
    }
}