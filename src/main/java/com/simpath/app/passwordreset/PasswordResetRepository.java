package com.simpath.app.passwordreset;

import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface PasswordResetRepository extends JpaRepository<PasswordResetToken, UUID> {
    @Query("select t.userId from PasswordResetToken t where t.tokenHash = :hash and t.usedAt is null and t.expiresAt > :now")
    Optional<UUID> findActiveOwner(@Param("hash") String hash, @Param("now") Instant now);

    Optional<PasswordResetToken> findByTokenHash(String hash);

    @Modifying(flushAutomatically = true)
    @Query("delete from PasswordResetToken t where t.userId = :userId and t.usedAt is null")
    int invalidateRemaining(@Param("userId") UUID userId);

    @Modifying
    @Query(value = """
        delete from password_reset_tokens where id in
        (select id from password_reset_tokens where expires_at < :cutoff order by expires_at limit :size)
        """, nativeQuery = true)
    int deleteExpired(@Param("cutoff") Instant cutoff, @Param("size") int size);
}
