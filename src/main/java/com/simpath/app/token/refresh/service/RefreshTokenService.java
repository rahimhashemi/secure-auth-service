package com.simpath.app.token.refresh.service;

import com.simpath.app.common.InvalidRefreshTokenException;
import com.simpath.app.token.refresh.entity.RefreshToken;
import com.simpath.app.token.refresh.repo.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final com.simpath.app.user.repo.UserRepository users;
    private final RefreshTokenRepository repo;
    private final RefreshTokenHasher hasher;
    private final com.simpath.app.session.SessionService sessions;
    private final long refreshTtlDays;
    private final SecureRandom random = new SecureRandom();

    public RefreshTokenService(RefreshTokenRepository repo, com.simpath.app.user.repo.UserRepository users, RefreshTokenHasher hasher, @Value("${app.jwt.refresh-ttl-days}") long refreshTtlDays, com.simpath.app.session.SessionService sessions) {
        this.repo = repo;
        this.users = users;
        this.hasher = hasher;
        this.sessions = sessions;
        this.refreshTtlDays = refreshTtlDays;
    }

    public record IssuedRefresh(UUID userId, String refreshTokenPlain, UUID tokenId, UUID familyId,
                                long expiresInSeconds) {
    }

    /**
     * Creates a new refresh token in a new family (new session).
     */
    @Transactional
    public IssuedRefresh issueNew(UUID userId, String userAgent, String ip) {
        lockUser(userId);
        UUID familyId = UUID.randomUUID();
        sessions.create(userId, familyId, Instant.now().plus(refreshTtlDays, ChronoUnit.DAYS), userAgent, ip);
        return createAndPersist(userId, familyId, userAgent, ip);
    }

    /**
     * Rotates refresh token inside the same family (same session).
     */
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public IssuedRefresh rotate(String refreshTokenPlain, String userAgent, String ip) {
        String hash = hasher.hash(refreshTokenPlain);

        lockOwner(hash);
        Instant now = Instant.now();
        RefreshToken current = repo.findByTokenHash(hash).orElse(null);

        if (current == null) {
            // An unknown token cannot identify a session to revoke.
            throw new InvalidRefreshTokenException("Invalid refresh token (possible reuse).");
        }

        // Expired history must never invalidate a live session.
        if (current.getExpiresAt() == null || !current.getExpiresAt().isAfter(now)) {
            throw new InvalidRefreshTokenException(InvalidRefreshTokenException.Reason.EXPIRED, current.getUserId(),
                    current.getFamilyId(), "Refresh token expired.");
        }

        if (current.getRevokedAt() != null || current.getReplacedBy() != null) {
            revokeFamily(current.getUserId(), current.getFamilyId());
            throw new InvalidRefreshTokenException(InvalidRefreshTokenException.Reason.REUSE, current.getUserId(),
                    current.getFamilyId(), "Refresh token reuse detected. Session family revoked.");
        }

        try {
            sessions.renew(current.getUserId(), current.getFamilyId(), now.plus(refreshTtlDays, ChronoUnit.DAYS));
        } catch (com.simpath.app.session.InvalidSessionException ex) {
            throw new InvalidRefreshTokenException(InvalidRefreshTokenException.Reason.INVALID,
                    current.getUserId(), current.getFamilyId(), "Session is inactive.");
        }

        // Revoke current & rotate
        current.setRevokedAt(now);

        IssuedRefresh next = createAndPersist(current.getUserId(), current.getFamilyId(), userAgent, ip);

        current.setReplacedBy(next.tokenId());
        repo.save(current);

        return next;
    }

    /**
     * Revoke all tokens in a family (logout all sessions of that device/session).
     */
    @Transactional
    public void revokeFamily(UUID userId, UUID familyId) {
        sessions.revoke(userId, familyId);
    }

    /**
     * Revoke all refresh tokens for user.
     */
    @Transactional
    public void revokeAll(UUID userId) {
        sessions.revokeAll(userId);
    }

    @Transactional
    public void revokeByRefreshToken(String refreshTokenPlain) {
        String hash = hasher.hash(refreshTokenPlain);

        lockOwner(hash);
        RefreshToken current = repo.findByTokenHash(hash).orElseThrow(() ->
                new InvalidRefreshTokenException("Invalid refresh token.")
        );

        sessions.revoke(current.getUserId(), current.getFamilyId());
    }


    private IssuedRefresh createAndPersist(UUID userId, UUID familyId, String userAgent, String ip) {
        Instant now = Instant.now();
        Instant exp = now.plus(refreshTtlDays, ChronoUnit.DAYS);

        String plain = generateOpaqueToken();
        String hash = hasher.hash(plain);

        RefreshToken rt = new RefreshToken();
        rt.setUserId(userId);
        rt.setFamilyId(familyId);
        rt.setTokenHash(hash);
        rt.setIssuedAt(now);
        rt.setExpiresAt(exp);
        rt.setUserAgent(userAgent);
        rt.setIp(ip);

        repo.save(rt);

        long expiresInSeconds = now.until(exp, ChronoUnit.SECONDS);
        return new IssuedRefresh(userId, plain, rt.getId(), familyId, expiresInSeconds);
    }

    private String generateOpaqueToken() {
        byte[] bytes = new byte[48]; // 384-bit
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Transactional
    public UUID getUserIdFromRefresh(String refreshTokenPlain) {
        String hash = hasher.hash(refreshTokenPlain);
        lockOwner(hash);
        RefreshToken token = repo.findByTokenHash(hash)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token."));
        if (token.getRevokedAt() != null || token.getReplacedBy() != null
                || token.getExpiresAt() == null || !token.getExpiresAt().isAfter(Instant.now())) {
            throw new InvalidRefreshTokenException("Invalid refresh token.");
        }
        try {
            sessions.authorize(token.getUserId(), token.getFamilyId());
        } catch (com.simpath.app.session.InvalidSessionException ex) {
            throw new InvalidRefreshTokenException("Session is inactive.");
        }
        return token.getUserId();
    }

    // Serialize session mutations per user, including rotations across different devices.
    private void lockOwner(String hash) {
        UUID userId = repo.findOwner(hash)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token."));
        lockUser(userId);
    }

    private void lockUser(UUID userId) {
        com.simpath.app.user.entity.User user = users.lockById(userId)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token."));
        if (!user.isEnabled()) {
            throw new InvalidRefreshTokenException(InvalidRefreshTokenException.Reason.USER_DISABLED, userId, null, "User is disabled.");
        }
    }
}

