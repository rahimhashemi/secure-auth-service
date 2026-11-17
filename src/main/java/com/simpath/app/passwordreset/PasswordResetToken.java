package com.simpath.app.passwordreset;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "password_reset_tokens")
@Getter
@Setter
public class PasswordResetToken {
    @Id private UUID id;
    @Column(nullable = false) private UUID userId;
    @Column(nullable = false, length = 64) private String tokenHash;
    @Column(nullable = false) private Instant expiresAt;
    private Instant usedAt;
}
