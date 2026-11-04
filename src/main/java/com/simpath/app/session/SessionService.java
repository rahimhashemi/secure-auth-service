package com.simpath.app.session;

import com.simpath.app.token.refresh.repo.RefreshTokenRepository;
import com.simpath.app.token.token.AuthPrincipal;
import com.simpath.app.user.repo.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.domain.PageRequest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class SessionService {
    private final SessionRepository sessions;
    private final UserRepository users;
    private final RefreshTokenRepository tokens;

    public SessionService(SessionRepository sessions, UserRepository users, RefreshTokenRepository tokens) {
        this.sessions = sessions;
        this.users = users;
        this.tokens = tokens;
    }

    @Transactional
    public AuthPrincipal authorize(UUID userId, UUID sessionId) {
        Instant now = Instant.now();
        SessionRepository.Access access = sessions.access(userId, sessionId, now).orElseThrow(InvalidSessionException::new);
        if (access.getLastSeenAt().isBefore(now.minusSeconds(60))) sessions.touch(sessionId, now, now.minusSeconds(60));
        return new AuthPrincipal(userId.toString(), access.getEmail(), sessionId.toString());
    }

    // Caller holds the user lock; session id equals the refresh family id.
    @Transactional
    public void create(UUID userId, UUID id, Instant expiry, String userAgent, String ip) {
        AuthSession session = new AuthSession();
        session.setId(id);
        session.setUserId(userId);
        session.setCreatedAt(Instant.now());
        session.setLastSeenAt(session.getCreatedAt());
        session.setExpiresAt(expiry);
        session.setUserAgent(truncate(userAgent));
        session.setIp(truncate(ip));
        sessions.save(session);
    }

    @Transactional(noRollbackFor = InvalidSessionException.class)
    public void renew(UUID userId, UUID id, Instant expiry) {
        AuthSession session = sessions.findByIdAndUserId(id, userId).orElseThrow(InvalidSessionException::new);
        if (session.getRevokedAt() != null || !session.getExpiresAt().isAfter(Instant.now())) throw new InvalidSessionException();
        session.setExpiresAt(expiry);
        session.setLastSeenAt(Instant.now());
    }

    @Transactional(readOnly = true)
    public List<SessionResponse> list(UUID userId, UUID currentId, int page, int size) {
        authorizeRead(userId, currentId);
        return sessions.active(userId, Instant.now(), PageRequest.of(page, size)).stream()
                .map(session -> new SessionResponse(session, currentId)).toList();
    }

    @Transactional
    public void revoke(UUID userId, UUID id) {
        lockUser(userId);
        sessions.findByIdAndUserId(id, userId).ifPresent(session -> {
            if (session.getRevokedAt() == null) session.setRevokedAt(Instant.now());
        });
        tokens.revokeFamily(userId, id, Instant.now());
    }

    @Transactional
    public void revokeAll(UUID userId) {
        lockUser(userId);
        sessions.revokeOthers(userId, null, Instant.now());
        tokens.revokeExcept(userId, null, Instant.now());
    }

    @Transactional
    public void revokeManaged(UUID userId, UUID callerId, UUID targetId) {
        lockUser(userId);
        authorizeRead(userId, callerId);
        revoke(userId, targetId);
    }

    @Transactional
    public void revokeOtherSessions(UUID userId, UUID callerId) {
        lockUser(userId);
        authorizeRead(userId, callerId);
        sessions.revokeOthers(userId, callerId, Instant.now());
        tokens.revokeExcept(userId, callerId, Instant.now());
    }

    private void authorizeRead(UUID userId, UUID id) {
        sessions.access(userId, id, Instant.now()).orElseThrow(InvalidSessionException::new);
    }

    private void lockUser(UUID userId) {
        if (users.lockById(userId).filter(user -> user.isEnabled() && user.isEmailVerified()).isEmpty()) throw new InvalidSessionException();
    }

    private String truncate(String value) { return value == null || value.length() <= 255 ? value : value.substring(0, 255); }
}
