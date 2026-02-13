package com.simpath.app.audit;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_events", indexes = {
        @Index(name = "idx_audit_user", columnList = "userId"),
        @Index(name = "idx_audit_type", columnList = "type")
})
@Getter
@Setter
public class AuditEvent {

    @Id
    private UUID id;

    @Column(nullable = false)
    private Instant at;

    private UUID userId;

    @Column(nullable = false, length = 60)
    private String type; // LOGIN_SUCCESS, LOGIN_FAIL, REFRESH_SUCCESS, REFRESH_REUSE, LOGOUT, LOGOUT_ALL...

    @Column(length = 500)
    private String detail;

    private String ip;
    private String userAgent;

    @PrePersist
    void prePersist() {
        if (id == null) id = UUID.randomUUID();
        if (at == null) at = Instant.now();
    }

}
