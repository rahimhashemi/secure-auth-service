package com.simpath.app.auth.service;

import com.simpath.app.auth.dto.AuthResponse;
import com.simpath.app.auth.dto.LoginRequest;
import com.simpath.app.auth.dto.RefreshRequest;
import com.simpath.app.auth.dto.RegisterRequest;
import com.simpath.app.security.PasswordService;
import com.simpath.app.token.refresh.service.RefreshTokenService;
import com.simpath.app.token.token.JwtService;
import com.simpath.app.user.entity.User;
import com.simpath.app.user.repo.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final UserRepository users;
    private final PasswordService passwordService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthService(UserRepository users, PasswordService passwordService, JwtService jwtService, RefreshTokenService refreshTokenService) {
        this.users = users;
        this.passwordService = passwordService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    @Transactional
    public void register(RegisterRequest req) {
        if (users.existsByEmailIgnoreCase(req.email())) {
            throw new IllegalArgumentException("Email already exists.");
        }
        User u = new User();
        u.setEmail(req.email().trim().toLowerCase());
        u.setPasswordHash(passwordService.hash(req.password()));
        users.save(u);
    }

    @Transactional
    public AuthResponse login(LoginRequest req, String userAgent, String ip) {
        User u = users.findByEmailIgnoreCase(req.email().trim()).orElseThrow(() -> new IllegalArgumentException("Invalid credentials."));
        if (!u.isEnabled()) throw new IllegalArgumentException("User disabled.");
        if (!passwordService.matches(req.password(), u.getPasswordHash()))
            throw new IllegalArgumentException("Invalid credentials.");

        String access = jwtService.issueAccessToken(u.getId(), u.getEmail());
        var refresh = refreshTokenService.issueNew(u.getId(), userAgent, ip);

        return new AuthResponse(access, jwtService.getAccessTtlSeconds(), refresh.refreshTokenPlain(), refresh.expiresInSeconds());
    }

    @Transactional
    public AuthResponse refresh(RefreshRequest req, String userAgent, String ip) {

        var rotated = refreshTokenService.rotate(req.refreshToken(), userAgent, ip);
        var user = users.findById(rotated.userId()).orElseThrow(() -> new IllegalStateException("User not found"));

        String access = jwtService.issueAccessToken(user.getId(), user.getEmail());

        return new AuthResponse(access, jwtService.getAccessTtlSeconds(), rotated.refreshTokenPlain(), rotated.expiresInSeconds());
    }
}