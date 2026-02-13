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
import java.util.List;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository repo;
    private final RefreshTokenHasher hasher;
    private final long refreshTtlDays;
    private final SecureRandom random = new SecureRandom();

    public RefreshTokenService(RefreshTokenRepository repo, RefreshTokenHasher hasher, @Value("${app.jwt.refresh-ttl-days}") long refreshTtlDays) {
        this.repo = repo;
        this.hasher = hasher;
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
        UUID familyId = UUID.randomUUID();
        return createAndPersist(userId, familyId, userAgent, ip);
    }

    /**
     * Rotates refresh token inside the same family (same session).
     */
    @Transactional
    public IssuedRefresh rotate(String refreshTokenPlain, String userAgent, String ip) {
        Instant now = Instant.now();
        String hash = hasher.hash(refreshTokenPlain);

        RefreshToken current = repo.findByTokenHash(hash).orElse(null);

        if (current == null) {
            // Reuse or unknown token: in a real system you might revoke all sessions for the user
            throw new InvalidRefreshTokenException("Invalid refresh token (possible reuse).");
        }

        // اگر قبلاً revoke شده یا rotate شده و دوباره استفاده شد => reuse
        if (current.getRevokedAt() != null || current.getReplacedBy() != null) {
            revokeAll(current.getUserId()); // واکنش امنیتی شدید
            throw new InvalidRefreshTokenException("Refresh token reuse detected. All sessions revoked.");
        }

//        if (!current.isActiveAt(now)) {
//            // If it's revoked/expired, also treat as invalid
//            throw new InvalidRefreshTokenException("Refresh token expired or revoked.");
//        }

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
        Instant now = Instant.now();
        List<RefreshToken> tokens = repo.findByUserIdAndFamilyId(userId, familyId);
        for (RefreshToken t : tokens) {
            if (t.getRevokedAt() == null) t.setRevokedAt(now);
        }
        repo.saveAll(tokens);
    }

    /**
     * Revoke all refresh tokens for user.
     */
    @Transactional
    public void revokeAll(UUID userId) {
        Instant now = Instant.now();
        List<RefreshToken> tokens = repo.findByUserId(userId);
        for (RefreshToken t : tokens) {
            if (t.getRevokedAt() == null) t.setRevokedAt(now);
        }
        repo.saveAll(tokens);
    }

    @Transactional
    public void revokeByRefreshToken(String refreshTokenPlain) {
        Instant now = Instant.now();
        String hash = hasher.hash(refreshTokenPlain);

        RefreshToken current = repo.findByTokenHash(hash).orElseThrow(() ->
                new IllegalArgumentException("Invalid refresh token.")
        );

        if (current.getRevokedAt() == null) {
            current.setRevokedAt(now);
            repo.save(current);
        }
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

    public UUID getUserIdFromRefresh(String refreshTokenPlain) {
        String hash = hasher.hash(refreshTokenPlain);
        return repo.findByTokenHash(hash)
                .map(RefreshToken::getUserId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token."));
    }

}