package com.simpath.app.verification;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
public interface MailOutboxRepository extends JpaRepository<MailOutbox, UUID> {
    @Query(value = "select * from mail_outbox where finished_at is null and next_attempt_at <= :now order by next_attempt_at, id limit 1 for update skip locked", nativeQuery = true)
    Optional<MailOutbox> claim(@Param("now") Instant now);
    @Modifying
    @Query(value = """
        update mail_outbox set payload = null, finished_at = :now where id in
        (select o.id from mail_outbox o join email_verification_tokens t on t.id = o.token_id
         join users u on u.id = t.user_id where o.finished_at is null and
         (o.expires_at <= :now or t.used_at is not null or u.email_verified = true or u.enabled = false)
         order by o.next_attempt_at limit 100 for update of o skip locked)
        """, nativeQuery = true)
    int scrubInactive(@Param("now") Instant now);
}
