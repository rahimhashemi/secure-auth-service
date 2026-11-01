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

    long deleteByExpiresAtBefore(Instant now);
}
