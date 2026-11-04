package com.simpath.app.user.repo;

import com.simpath.app.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.Query("select u from User u where u.id = :id")
    Optional<User> lockById(@org.springframework.data.repository.query.Param("id") UUID id);

    Optional<User> findByEmail(String email);

    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.data.jpa.repository.Query(value = """
            INSERT INTO users(id, email, password_hash, enabled, created_at)
            VALUES (:id, :email, :hash, true, :createdAt)
            ON CONFLICT (email) DO NOTHING
            """, nativeQuery = true)
    int insertIfAbsent(@org.springframework.data.repository.query.Param("id") UUID id,
                       @org.springframework.data.repository.query.Param("email") String email,
                       @org.springframework.data.repository.query.Param("hash") String hash,
                       @org.springframework.data.repository.query.Param("createdAt") java.time.Instant createdAt);
}


