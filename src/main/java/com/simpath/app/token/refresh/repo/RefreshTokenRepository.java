package com.simpath.app.token.refresh.repo;


import com.simpath.app.token.refresh.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    @org.springframework.data.jpa.repository.Query("select t.userId from RefreshToken t where t.tokenHash = :hash")
    Optional<UUID> findOwner(@org.springframework.data.repository.query.Param("hash") String hash);

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findByUserIdAndFamilyId(UUID userId, UUID familyId);

    List<RefreshToken> findByUserId(UUID userId);

    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.data.jpa.repository.Query(value = """
            DELETE FROM refresh_tokens WHERE id IN (
                SELECT id FROM refresh_tokens WHERE expires_at < :cutoff
                ORDER BY expires_at LIMIT :batchSize
            )
            """, nativeQuery = true)
    int deleteExpiredBatch(@org.springframework.data.repository.query.Param("cutoff") Instant cutoff,
                           @org.springframework.data.repository.query.Param("batchSize") int batchSize);
}

