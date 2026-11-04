package com.simpath.app.session;

import lombok.Getter;
import java.time.Instant;
import java.util.UUID;

@Getter
public class SessionResponse {
    private final UUID id;
    private final Instant createdAt;
    private final Instant lastSeenAt;
    private final Instant expiresAt;
    private final String userAgent;
    private final String ip;
    private final boolean current;

    public SessionResponse(AuthSession session, UUID currentId) {
        this.id = session.getId();
        this.createdAt = session.getCreatedAt();
        this.lastSeenAt = session.getLastSeenAt();
        this.expiresAt = session.getExpiresAt();
        this.userAgent = session.getUserAgent();
        this.ip = session.getIp();
        this.current = session.getId().equals(currentId);
    }
}
