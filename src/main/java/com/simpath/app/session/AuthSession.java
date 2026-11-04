package com.simpath.app.session;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "auth_sessions")
@Getter
@Setter
public class AuthSession {
    @Id private UUID id;
    @Column(nullable = false) private UUID userId;
    @Column(nullable = false) private Instant createdAt;
    @Column(nullable = false) private Instant lastSeenAt;
    @Column(nullable = false) private Instant expiresAt;
    private Instant revokedAt;
    @Column(length = 255) private String userAgent;
    @Column(length = 255) private String ip;
}
