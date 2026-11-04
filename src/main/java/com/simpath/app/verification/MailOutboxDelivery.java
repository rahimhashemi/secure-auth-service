package com.simpath.app.verification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;
import java.time.Instant;
@Service
public class MailOutboxDelivery {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(MailOutboxDelivery.class);
    private final MailOutboxRepository outbox;
    private final VerificationRepository tokens;
    private final OutboxCipher cipher;
    private final VerificationMailer mail;
    public MailOutboxDelivery(MailOutboxRepository outbox, VerificationRepository tokens, OutboxCipher cipher, VerificationMailer mail) {
        this.outbox = outbox; this.tokens = tokens; this.cipher = cipher; this.mail = mail;
    }
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean deliverOne() {
        MailOutbox item = outbox.claim(Instant.now()).orElse(null);
        if (item == null) return false;
        if (item.getPayload() == null || item.getAttempts() >= 5 || !item.getExpiresAt().isAfter(Instant.now())
                || !tokens.deliverable(item.getTokenId(), Instant.now())) { item.finish(); return true; }
        item.setAttempts(item.getAttempts() + 1);
        try {
            String[] payload = cipher.decrypt(item.getId(), item.getPayload()).split("\n", 2);
            if (payload.length != 2) throw new IllegalStateException("Invalid mail payload");
            mail.send(payload[0], payload[1]); item.finish();
        } catch (RuntimeException ex) {
            // SMTP exceptions can contain addresses or message content: never log them.
            LOG.warn("Verification delivery failed outbox={} attempt={}", item.getId(), item.getAttempts());
            if (item.getAttempts() >= 5) item.finish();
            else item.setNextAttemptAt(Instant.now().plusSeconds(30L << (item.getAttempts() - 1)));
        }
        return true;
    }
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void scrub() { outbox.scrubInactive(Instant.now()); }
}
