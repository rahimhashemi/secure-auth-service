package com.simpath.app.mfa;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface UserMfaRepository extends JpaRepository<UserMfa, UUID> {
}
