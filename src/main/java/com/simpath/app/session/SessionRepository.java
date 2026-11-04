package com.simpath.app.session;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.query.Param;
import org.springframework.data.domain.Pageable;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SessionRepository extends JpaRepository<AuthSession, UUID> {
    interface Access {
        UUID getUserId();
        String getEmail();
        Instant getLastSeenAt();
    }

    @Query("""
            select s.userId as userId, u.email as email, s.lastSeenAt as lastSeenAt
            from AuthSession s, User u where s.id = :sid and s.userId = :uid
            and u.id = s.userId and u.enabled = true and s.revokedAt is null and s.expiresAt > :now
            """)
    Optional<Access> access(@Param("uid") UUID userId, @Param("sid") UUID sessionId, @Param("now") Instant now);

    Optional<AuthSession> findByIdAndUserId(UUID id, UUID userId);

    @Query("select s from AuthSession s where s.userId = :uid and s.revokedAt is null and s.expiresAt > :now order by s.createdAt desc, s.id desc")
    List<AuthSession> active(@Param("uid") UUID userId, @Param("now") Instant now, Pageable page);

    @Modifying
    @Query("update AuthSession s set s.lastSeenAt = :now where s.id = :sid and s.revokedAt is null and s.expiresAt > :now and s.lastSeenAt < :before")
    int touch(@Param("sid") UUID id, @Param("now") Instant now, @Param("before") Instant before);

    @Modifying
    @Query("update AuthSession s set s.revokedAt = :now where s.userId = :uid and s.revokedAt is null and (:keep is null or s.id <> :keep)")
    int revokeOthers(@Param("uid") UUID userId, @Param("keep") UUID keep, @Param("now") Instant now);

    @Modifying
    @Query(value = "delete from auth_sessions where id in (select id from auth_sessions where expires_at < :cutoff order by expires_at limit :batchSize)", nativeQuery = true)
    int deleteExpiredBatch(@Param("cutoff") Instant cutoff, @Param("batchSize") int batchSize);
}
