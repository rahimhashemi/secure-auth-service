package com.simpath.app.auth.service;

import com.simpath.app.audit.AuditService;
import com.simpath.app.auth.dto.*;
import com.simpath.app.common.InvalidRefreshTokenException;
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
    private final AuditService audit;

    public AuthService(UserRepository users, PasswordService passwordService, JwtService jwtService, RefreshTokenService refreshTokenService, AuditService audit) {
        this.users = users;
        this.passwordService = passwordService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.audit = audit;
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
        var email = req.email().trim();
        var u = users.findByEmailIgnoreCase(email).orElse(null);

        if (u == null || !u.isEnabled() || !passwordService.matches(req.password(), u.getPasswordHash())) {
            audit.log("LOGIN_FAIL", u != null ? u.getId() : null, "invalid_credentials", ip, userAgent);
            throw new IllegalArgumentException("Invalid credentials.");
        }

        audit.log("LOGIN_SUCCESS", u.getId(), null, ip, userAgent);

        String access = jwtService.issueAccessToken(u.getId(), u.getEmail());
        var refresh = refreshTokenService.issueNew(u.getId(), userAgent, ip);

        return new AuthResponse(access, jwtService.getAccessTtlSeconds(), refresh.refreshTokenPlain(), refresh.expiresInSeconds());
    }

    @Transactional
    public AuthResponse refresh(RefreshRequest req, String userAgent, String ip) {
        try {
            var rotated = refreshTokenService.rotate(req.refreshToken(), userAgent, ip);
            var user = users.findById(rotated.userId()).orElseThrow();

            audit.log("REFRESH_SUCCESS", user.getId(), null, ip, userAgent);

            String access = jwtService.issueAccessToken(user.getId(), user.getEmail());
            return new AuthResponse(access, jwtService.getAccessTtlSeconds(), rotated.refreshTokenPlain(), rotated.expiresInSeconds());
        } catch (InvalidRefreshTokenException ex) {
            audit.log("REFRESH_FAIL", null, ex.getMessage(), ip, userAgent);
            throw ex;
        }
    }

    @Transactional
    public void logout(LogoutRequest req, String userAgent, String ip) {
        var userId = refreshTokenService.getUserIdFromRefresh(req.refreshToken());
        refreshTokenService.revokeByRefreshToken(req.refreshToken());
        audit.log("LOGOUT", userId, null, ip, userAgent);
    }

    @Transactional
    public void logoutAll(LogoutRequest req, String userAgent, String ip) {
        var userId = refreshTokenService.getUserIdFromRefresh(req.refreshToken());
        refreshTokenService.revokeAll(userId);
        audit.log("LOGOUT_ALL", userId, null, ip, userAgent);
    }

}