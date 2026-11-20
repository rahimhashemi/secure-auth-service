package com.simpath.app.mfa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface MfaLoginChallengeRepository extends JpaRepository<MfaLoginChallenge, String> {
    @Query("select c.userId from MfaLoginChallenge c where c.tokenHash = :hash")
    Optional<UUID> findOwner(@Param("hash") String hash);

    @Modifying
    @Query(value = "delete from mfa_login_challenges where token_hash in (select token_hash from mfa_login_challenges where expires_at < :cutoff order by expires_at limit :batchSize)", nativeQuery = true)
    int deleteExpired(@Param("cutoff") Instant cutoff, @Param("batchSize") int batchSize);
}
