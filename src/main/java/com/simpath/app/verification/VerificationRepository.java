package com.simpath.app.verification;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
public interface VerificationRepository extends JpaRepository<VerificationToken, UUID> {
    Optional<VerificationToken> findByTokenHash(String hash);
    @Query("select count(t) > 0 from VerificationToken t, User u where t.id = :id and t.userId = u.id and t.usedAt is null and t.expiresAt > :now and u.enabled = true and u.emailVerified = false")
    boolean deliverable(@Param("id") UUID id, @Param("now") Instant now);
    @Modifying
    @Query(value = "delete from email_verification_tokens where id in (select id from email_verification_tokens where expires_at < :cutoff order by expires_at limit :size)", nativeQuery = true)
    int deleteExpired(@Param("cutoff") Instant cutoff, @Param("size") int size);
}
