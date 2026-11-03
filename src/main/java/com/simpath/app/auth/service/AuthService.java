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
    private final com.simpath.app.security.RateLimitService rateLimits;

    public AuthService(UserRepository users, PasswordService passwordService, JwtService jwtService, RefreshTokenService refreshTokenService, AuditService audit, com.simpath.app.security.RateLimitService rateLimits) {
        this.users = users;
        this.passwordService = passwordService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.audit = audit;
        this.rateLimits = rateLimits;
    }

    @Transactional
    public void register(RegisterRequest req) {
        String email = req.email().trim().toLowerCase(java.util.Locale.ROOT);
        String passwordHash = passwordService.hash(req.password());
        // Hash in both cases; atomically suppress only the duplicate email conflict.
        users.insertIfAbsent(java.util.UUID.randomUUID(), email, passwordHash, java.time.Instant.now());
    }

    @Transactional
    public AuthResponse login(LoginRequest req, String userAgent, String ip) {
        String email = req.email().trim().toLowerCase(java.util.Locale.ROOT);
        rateLimits.enforceLoginAccount(email);
        User u = users.findByEmailIgnoreCase(email).orElse(null);

        boolean passwordMatches = passwordService.matches(req.password(), u == null ? null : u.getPasswordHash());
        if (u == null || !u.isEnabled() || !passwordMatches) {
            audit.log("LOGIN_FAIL", u != null ? u.getId() : null, "invalid_credentials", ip, userAgent);
            throw new com.simpath.app.common.InvalidCredentialsException();
        }

        audit.log("LOGIN_SUCCESS", u.getId(), null, ip, userAgent);

        String access = jwtService.issueAccessToken(u.getId(), u.getEmail());
        RefreshTokenService.IssuedRefresh refresh = refreshTokenService.issueNew(u.getId(), userAgent, ip);

        return new AuthResponse(access, jwtService.getAccessTtlSeconds(), refresh.refreshTokenPlain(), refresh.expiresInSeconds());
    }

    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public AuthResponse refresh(RefreshRequest req, String userAgent, String ip) {
        try {
            RefreshTokenService.IssuedRefresh rotated = refreshTokenService.rotate(req.refreshToken(), userAgent, ip);
            User user = users.findById(rotated.userId()).orElseThrow();

            audit.log("REFRESH_SUCCESS", user.getId(), null, ip, userAgent);

            String access = jwtService.issueAccessToken(user.getId(), user.getEmail());
            return new AuthResponse(access, jwtService.getAccessTtlSeconds(), rotated.refreshTokenPlain(), rotated.expiresInSeconds());
        } catch (InvalidRefreshTokenException ex) {
            audit.log(ex.getMessage().contains("reuse detected") ? "REFRESH_REUSE" : "REFRESH_FAIL",
                    null, ex.getMessage(), ip, userAgent);
            throw ex;
        }
    }

    @Transactional
    public void logout(LogoutRequest req, String userAgent, String ip) {
        java.util.UUID userId = refreshTokenService.getUserIdFromRefresh(req.refreshToken());
        refreshTokenService.revokeByRefreshToken(req.refreshToken());
        audit.log("LOGOUT", userId, null, ip, userAgent);
    }

    @Transactional
    public void logoutAll(LogoutRequest req, String userAgent, String ip) {
        java.util.UUID userId = refreshTokenService.getUserIdFromRefresh(req.refreshToken());
        refreshTokenService.revokeAll(userId);
        audit.log("LOGOUT_ALL", userId, null, ip, userAgent);
    }

}

