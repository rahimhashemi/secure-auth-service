package com.simpath.app.common;

import java.util.UUID;

public class InvalidRefreshTokenException extends RuntimeException {
    public enum Reason { INVALID, EXPIRED, REUSE, USER_DISABLED }
    private final Reason reason;
    private final UUID userId;
    private final UUID familyId;
    public InvalidRefreshTokenException(String message) { this(Reason.INVALID, null, null, message); }
    public InvalidRefreshTokenException(Reason reason, UUID userId, UUID familyId, String message) {
        super(message); this.reason = reason; this.userId = userId; this.familyId = familyId;
    }
    public Reason getReason() { return reason; }
    public UUID getUserId() { return userId; }
    public UUID getFamilyId() { return familyId; }
}
