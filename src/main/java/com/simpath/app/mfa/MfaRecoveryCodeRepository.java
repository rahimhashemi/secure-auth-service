package com.simpath.app.mfa;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface MfaRecoveryCodeRepository extends JpaRepository<MfaRecoveryCode, UUID> {
    Optional<MfaRecoveryCode> findByUserIdAndCodeHash(UUID userId, String codeHash);
    void deleteByUserId(UUID userId);
}
