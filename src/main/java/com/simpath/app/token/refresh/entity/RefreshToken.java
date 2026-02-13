package com.simpath.app.token.refresh.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_refresh_user", columnList = "user_id"),
        @Index(name = "idx_refresh_family", columnList = "family_id")
})
public class RefreshToken {
    @Id
    @UuidGenerator
    @Column(columnDefinition = "uuid")
    private UUID id;

    @Column(nullable = false)
    private UUID userId;

    @Column(nullable = false, length = 128)
    private String tokenHash; // SHA-256(base64) or HMAC-SHA256

    @Column(nullable = false)
    private UUID familyId; // session family for logout-all

    private Instant issuedAt;
    private Instant expiresAt;

    private Instant revokedAt;

    private UUID replacedBy; // token id that replaced this one (rotation)
    private String userAgent;
    private String ip;

    @PrePersist
    void prePersist() {
        if (id == null) id = UUID.randomUUID();
        if (issuedAt == null) issuedAt = Instant.now();
    }
}