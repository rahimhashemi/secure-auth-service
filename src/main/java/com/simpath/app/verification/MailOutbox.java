package com.simpath.app.verification;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.Instant;
import java.util.UUID;
@Entity @Table(name = "mail_outbox")
@Getter @Setter
public class MailOutbox {
    @Id private UUID id;
    @Column(nullable = false) private UUID tokenId;
    @Column(columnDefinition = "text") private String payload;
    @Column(nullable = false) private int attempts;
    @Column(nullable = false) private Instant nextAttemptAt;
    @Column(nullable = false) private Instant expiresAt;
    private Instant finishedAt;
    public void finish() { payload = null; finishedAt = Instant.now(); }
}
