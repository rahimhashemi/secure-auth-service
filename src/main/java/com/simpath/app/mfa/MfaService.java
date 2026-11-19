package com.simpath.app.mfa;

import com.simpath.app.audit.AuditService;
import com.simpath.app.auth.dto.AuthResponse;
import com.simpath.app.security.PasswordService;
import com.simpath.app.security.RateLimitService;
import com.simpath.app.session.SessionService;
import com.simpath.app.token.refresh.service.RefreshTokenService;
import com.simpath.app.token.token.JwtService;
import com.simpath.app.user.entity.User;
import com.simpath.app.user.repo.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Service
public class MfaService {
    private final UserRepository users;
    private final UserMfaRepository factors;
    private final MfaRecoveryCodeRepository recoveryCodes;
    private final MfaLoginChallengeRepository challenges;
    private final TotpService totp;
    private final MfaCipher cipher;
    private final PasswordService passwords;
    private final RateLimitService limits;
    private final SessionService sessions;
    private final RefreshTokenService refreshTokens;
    private final JwtService jwt;
    private final AuditService audit;
    private final byte[] recoveryPepper;
    private final SecureRandom random = new SecureRandom();

    public MfaService(UserRepository users, UserMfaRepository factors,
            MfaRecoveryCodeRepository recoveryCodes, MfaLoginChallengeRepository challenges,
            TotpService totp, MfaCipher cipher, PasswordService passwords, RateLimitService limits,
            SessionService sessions, RefreshTokenService refreshTokens, JwtService jwt, AuditService audit,
            @Value("${app.mfa.recovery-pepper}") String recoveryPepper) {
        if (recoveryPepper == null || recoveryPepper.length() < 32) {
            throw new IllegalArgumentException("MFA recovery pepper must have at least 32 characters.");
        }
        this.users = users;
        this.factors = factors;
        this.recoveryCodes = recoveryCodes;
        this.challenges = challenges;
        this.totp = totp;
        this.cipher = cipher;
        this.passwords = passwords;
        this.limits = limits;
        this.sessions = sessions;
        this.refreshTokens = refreshTokens;
        this.jwt = jwt;
        this.audit = audit;
        this.recoveryPepper = recoveryPepper.getBytes(StandardCharsets.UTF_8);
    }

    @Transactional(readOnly = true)
    public boolean isEnabled(UUID userId) {
        return factors.findById(userId).map(factor -> factor.getEnabledAt() != null).orElse(false);
    }

    // Called only after a successful password check while holding the user row lock.
    @Transactional
    public String issueChallenge(User user) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String plain = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        MfaLoginChallenge challenge = new MfaLoginChallenge();
        challenge.setTokenHash(sha256(plain));
        challenge.setUserId(user.getId());
        // A password reset invalidates pending login challenges, including ones already handed out.
        challenge.setPasswordHash(user.getPasswordHash());
        challenge.setExpiresAt(Instant.now().plusSeconds(300));
        challenges.save(challenge);
        return plain;
    }

    @Transactional(readOnly = true)
    public MfaDtos.StatusResponse status(UUID userId) {
        return factors.findById(userId)
                .map(factor -> new MfaDtos.StatusResponse(factor.getEnabledAt() != null, factor.getEnabledAt() == null))
                .orElseGet(() -> new MfaDtos.StatusResponse(false, false));
    }

    @Transactional
    public MfaDtos.SetupResponse setup(UUID userId, String password, String ip, String agent) {
        User user = activeLockedUser(userId);
        verifyPassword(user, password);
        UserMfa factor = factors.findById(userId).orElseGet(() -> {
            UserMfa created = new UserMfa();
            created.setUserId(userId);
            return created;
        });
        if (factor.getEnabledAt() != null) throw new InvalidMfaException();
        String secret = totp.generateSecret();
        factor.setSecretCiphertext(cipher.encrypt(userId, secret));
        factor.setLastUsedCounter(-1);
        factors.save(factor);
        audit.log("MFA_SETUP_STARTED", userId, null, ip, agent);
        return new MfaDtos.SetupResponse(secret, totp.provisioningUri(user.getEmail(), secret));
    }

    @Transactional
    public MfaDtos.RecoveryResponse confirm(UUID userId, String code, String ip, String agent) {
        User user = activeLockedUser(userId);
        limits.enforceLoginAccount(user.getEmail());
        UserMfa factor = factors.findById(userId).orElseThrow(InvalidMfaException::new);
        if (factor.getEnabledAt() != null) throw new InvalidMfaException();
        long counter = totp.verify(cipher.decrypt(userId, factor.getSecretCiphertext()),
                code, Instant.now(), factor.getLastUsedCounter());
        if (counter < 0) {
            failedFactor(user);
            throw new InvalidMfaException();
        }
        factor.setLastUsedCounter(counter);
        factor.setEnabledAt(Instant.now());
        List<String> plainCodes = replaceRecoveryCodes(userId);
        // Even the session used to enroll must not remain active without MFA.
        sessions.revokeAll(userId);
        audit.log("MFA_ENABLED", userId, null, ip, agent);
        return new MfaDtos.RecoveryResponse(plainCodes);
    }

    @Transactional(noRollbackFor = InvalidMfaException.class)
    public AuthResponse verifyChallenge(String plainChallenge, String code, String agent, String ip) {
        if (plainChallenge == null || !plainChallenge.matches("[A-Za-z0-9_-]{43}")) {
            throw new InvalidMfaException();
        }
        String hash = sha256(plainChallenge);
        // Scalar lookup before the lock avoids caching a stale challenge entity.
        UUID owner = challenges.findOwner(hash).orElseThrow(InvalidMfaException::new);
        User user = activeLockedUser(owner);
        MfaLoginChallenge challenge = challenges.findById(hash).orElseThrow(InvalidMfaException::new);
        Instant now = Instant.now();
        if (challenge.getConsumedAt() != null || !challenge.getExpiresAt().isAfter(now)
                || challenge.getFailedAttempts() >= 5
                || !challenge.getPasswordHash().equals(user.getPasswordHash())) {
            throw new InvalidMfaException();
        }
        UserMfa factor = enabledFactor(owner);
        limits.enforceLoginAccount(user.getEmail());
        if (!verifyFactor(factor, code, true)) {
            challenge.setFailedAttempts(challenge.getFailedAttempts() + 1);
            if (challenge.getFailedAttempts() >= 5) challenge.setConsumedAt(now);
            failedFactor(user);
            audit.log("MFA_CHALLENGE_FAILED", owner, null, ip, agent);
            throw new InvalidMfaException();
        }
        challenge.setConsumedAt(now);
        RefreshTokenService.IssuedRefresh refresh = refreshTokens.issueNew(owner, agent, ip);
        String access = jwt.issueAccessToken(owner, user.getEmail(), refresh.familyId());
        audit.log("LOGIN_SUCCESS", owner, "mfa_verified", ip, agent);
        return new AuthResponse(access, jwt.getAccessTtlSeconds(), refresh.refreshTokenPlain(), refresh.expiresInSeconds());
    }

    @Transactional
    public MfaDtos.RecoveryResponse regenerate(UUID userId, String password, String code, String ip, String agent) {
        User user = activeLockedUser(userId);
        verifyPassword(user, password);
        UserMfa factor = enabledFactor(userId);
        if (!verifyFactor(factor, code, false)) {
            failedFactor(user);
            throw new InvalidMfaException();
        }
        List<String> plainCodes = replaceRecoveryCodes(userId);
        sessions.revokeAll(userId);
        audit.log("MFA_RECOVERY_REGENERATED", userId, null, ip, agent);
        return new MfaDtos.RecoveryResponse(plainCodes);
    }

    @Transactional
    public void disable(UUID userId, String password, String code, String ip, String agent) {
        User user = activeLockedUser(userId);
        verifyPassword(user, password);
        UserMfa factor = enabledFactor(userId);
        if (!verifyFactor(factor, code, true)) {
            failedFactor(user);
            throw new InvalidMfaException();
        }
        recoveryCodes.deleteByUserId(userId);
        factors.delete(factor);
        sessions.revokeAll(userId);
        audit.log("MFA_DISABLED", userId, null, ip, agent);
    }

    private User activeLockedUser(UUID userId) {
        return users.lockById(userId).filter(user -> user.isEnabled() && user.isEmailVerified())
                .orElseThrow(InvalidMfaException::new);
    }

    private UserMfa enabledFactor(UUID userId) {
        return factors.findById(userId).filter(factor -> factor.getEnabledAt() != null)
                .orElseThrow(InvalidMfaException::new);
    }

    private void verifyPassword(User user, String password) {
        limits.enforceLoginAccount(user.getEmail());
        if (!passwords.matches(password, user.getPasswordHash())) {
            failedFactor(user);
            throw new InvalidMfaException();
        }
    }

    private void failedFactor(User user) {
        limits.recordFailedLogin(user.getEmail());
    }

    private boolean verifyFactor(UserMfa factor, String code, boolean allowRecovery) {
        long counter = totp.verify(cipher.decrypt(factor.getUserId(), factor.getSecretCiphertext()),
                code, Instant.now(), factor.getLastUsedCounter());
        if (counter >= 0) {
            factor.setLastUsedCounter(counter);
            return true;
        }
        if (!allowRecovery || code == null || !code.matches("[A-Za-z0-9_-]{22}")) return false;
        MfaRecoveryCode saved = recoveryCodes.findByUserIdAndCodeHash(factor.getUserId(), hashRecovery(code))
                .orElse(null);
        if (saved == null || saved.getUsedAt() != null) return false;
        saved.setUsedAt(Instant.now());
        return true;
    }

    private List<String> replaceRecoveryCodes(UUID userId) {
        recoveryCodes.deleteByUserId(userId);
        List<String> plainCodes = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);
            String plain = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            MfaRecoveryCode item = new MfaRecoveryCode();
            item.setId(UUID.randomUUID());
            item.setUserId(userId);
            item.setCodeHash(hashRecovery(plain));
            recoveryCodes.save(item);
            plainCodes.add(plain);
        }
        return plainCodes;
    }

    private String hashRecovery(String plain) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(recoveryPepper, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Recovery hash unavailable.", ex);
        }
    }

    private static String sha256(String plain) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(plain.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("SHA-256 unavailable.", ex);
        }
    }
}
