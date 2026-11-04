package com.simpath.app.verification;
import com.simpath.app.security.EmailNormalizer;
import com.simpath.app.security.RateLimitService;
import com.simpath.app.user.entity.User;
import com.simpath.app.user.repo.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
@Service
public class VerificationService {
    private final UserRepository users;
    private final com.simpath.app.audit.AuditService audit;
    private final VerificationRepository tokens;
    private final MailOutboxRepository outbox;
    private final OutboxCipher cipher;
    private final RateLimitService limits;
    private final SecureRandom random = new SecureRandom();
    public VerificationService(UserRepository users, VerificationRepository tokens, MailOutboxRepository outbox, OutboxCipher cipher, RateLimitService limits, com.simpath.app.audit.AuditService audit) {
        this.audit = audit; this.users = users; this.tokens = tokens; this.outbox = outbox; this.cipher = cipher; this.limits = limits;
    }
    @Transactional
    public void issueNewAccount(UUID userId) {
        queue(users.lockById(userId).orElseThrow());
    }
    @Transactional
    public void request(String suppliedEmail) {
        String email = EmailNormalizer.normalize(suppliedEmail);
        limits.enforceVerificationAccount(email);
        users.lockByEmail(email).ifPresent(this::queue);
    }
    private void queue(User user) {
        Instant now = Instant.now();
        if (!user.isEnabled() || user.isEmailVerified()
                || (user.getVerificationSentAt() != null && user.getVerificationSentAt().isAfter(now.minusSeconds(60)))) return;
        byte[] bytes = new byte[32]; random.nextBytes(bytes);
        String plain = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        VerificationToken token = new VerificationToken();
        token.setId(UUID.randomUUID()); token.setUserId(user.getId()); token.setTokenHash(hash(plain));
        token.setCreatedAt(now); token.setExpiresAt(now.plusSeconds(1800));
        tokens.save(token);
        MailOutbox item = new MailOutbox();
        item.setId(UUID.randomUUID()); item.setTokenId(token.getId());
        item.setPayload(cipher.encrypt(item.getId(), user.getEmail() + "\n" + plain));
        item.setNextAttemptAt(now); item.setExpiresAt(token.getExpiresAt()); outbox.save(item);
        user.setVerificationSentAt(now);
    }
    @Transactional
    public void confirm(String plain) {
        if (plain == null || !plain.matches("[A-Za-z0-9_-]{43}")) throw new InvalidVerificationException();
        VerificationToken candidate = tokens.findByTokenHash(hash(plain)).orElseThrow(InvalidVerificationException::new);
        User user = users.lockById(candidate.getUserId()).orElseThrow(InvalidVerificationException::new);
        // The freshly locked owner flag serializes all token consumers, including different links.
        if (!user.isEnabled() || user.isEmailVerified() || candidate.getUsedAt() != null || !candidate.getExpiresAt().isAfter(Instant.now())) {
            throw new InvalidVerificationException();
        }
        candidate.setUsedAt(Instant.now()); user.setEmailVerified(true);
        audit.log("EMAIL_VERIFIED", user.getId(), null, null, null);
    }
    public static String hash(String plain) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(plain.getBytes(StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException ex) { throw new IllegalStateException("SHA-256 unavailable", ex); }
    }
}
