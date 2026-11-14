package com.simpath.app.passwordreset;

import com.simpath.app.security.EmailNormalizer;
import com.simpath.app.security.PasswordService;
import com.simpath.app.security.RateLimitService;
import com.simpath.app.session.SessionService;
import com.simpath.app.user.entity.User;
import com.simpath.app.user.repo.UserRepository;
import com.simpath.app.verification.MailOutbox;
import com.simpath.app.verification.MailOutboxRepository;
import com.simpath.app.verification.OutboxCipher;
import com.simpath.app.verification.VerificationService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
public class PasswordResetService {
    private final UserRepository users;
    private final PasswordResetRepository tokens;
    private final MailOutboxRepository outbox;
    private final OutboxCipher cipher;
    private final RateLimitService limits;
    private final PasswordService passwords;
    private final SessionService sessions;
    private final SecureRandom random = new SecureRandom();

    public PasswordResetService(UserRepository users, PasswordResetRepository tokens,
            MailOutboxRepository outbox, OutboxCipher cipher, RateLimitService limits,
            PasswordService passwords, SessionService sessions) {
        this.users = users;
        this.tokens = tokens;
        this.outbox = outbox;
        this.cipher = cipher;
        this.limits = limits;
        this.passwords = passwords;
        this.sessions = sessions;
    }

    @Transactional
    public void request(String suppliedEmail) {
        String email = EmailNormalizer.normalize(suppliedEmail);
        limits.enforcePasswordResetAccount(email);
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String plain = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String hash = VerificationService.hash(plain);

        users.lockByEmail(email).filter(user -> user.isEnabled() && user.isEmailVerified()).ifPresent(user -> {
            Instant now = Instant.now();
            PasswordResetToken token = new PasswordResetToken();
            token.setId(UUID.randomUUID());
            token.setUserId(user.getId());
            token.setTokenHash(hash);
            token.setExpiresAt(now.plusSeconds(900));
            tokens.save(token);
            enqueue(token, email + "\n" + plain, false, now, token.getExpiresAt());
        });
    }

    @Transactional
    public void confirm(String plain, String newPassword) {
        if (plain == null || !plain.matches("[A-Za-z0-9_-]{43}")) {
            throw new InvalidPasswordResetException();
        }
        String hash = VerificationService.hash(plain);
        // Read a scalar before acquiring the user lock so the token entity is never cached stale.
        UUID owner = tokens.findActiveOwner(hash, Instant.now()).orElseThrow(InvalidPasswordResetException::new);
        User user = users.lockById(owner).filter(u -> u.isEnabled() && u.isEmailVerified())
                .orElseThrow(InvalidPasswordResetException::new);
        PasswordResetToken token = tokens.findByTokenHash(hash).orElseThrow(InvalidPasswordResetException::new);
        if (token.getUsedAt() != null || !token.getExpiresAt().isAfter(Instant.now())) {
            throw new InvalidPasswordResetException();
        }
        user.setPasswordHash(passwords.hash(newPassword));
        Instant now = Instant.now();
        token.setUsedAt(now);
        tokens.invalidateRemaining(owner);
        sessions.revokeAll(owner);
        enqueue(token, user.getEmail(), true, now, now.plusSeconds(3600));
    }

    private void enqueue(PasswordResetToken token, String payload, boolean notice, Instant now, Instant expiresAt) {
        MailOutbox item = new MailOutbox();
        item.setId(UUID.randomUUID());
        item.setResetTokenId(token.getId());
        item.setResetNotice(notice);
        item.setPayload(cipher.encrypt(item.getId(), payload));
        item.setNextAttemptAt(now);
        item.setExpiresAt(expiresAt);
        outbox.save(item);
    }
}
