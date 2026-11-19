package com.simpath.app.mfa;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_mfa")
@Getter
@Setter
public class UserMfa {
    @Id
    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(nullable = false, length = 512)
    private String secretCiphertext;

    private Instant enabledAt;

    @Column(nullable = false)
    private long lastUsedCounter = -1L;
}
