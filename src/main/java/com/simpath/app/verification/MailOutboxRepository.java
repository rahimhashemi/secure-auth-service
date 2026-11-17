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
        (select o.id from mail_outbox o
         left join email_verification_tokens t on t.id = o.token_id
         left join password_reset_tokens r on r.id = o.reset_token_id
         join users u on u.id = coalesce(t.user_id, r.user_id)
         where o.finished_at is null and
         (o.expires_at <= :now
          or (o.token_id is not null and (t.used_at is not null or u.email_verified or not u.enabled))
          or (o.reset_token_id is not null and not o.reset_notice
              and (r.used_at is not null or r.expires_at <= :now or not u.email_verified or not u.enabled)))
         order by o.next_attempt_at limit 100 for update of o skip locked)
        """, nativeQuery = true)
    int scrubInactive(@Param("now") Instant now);
    @Query(value = """
        select exists (select 1 from password_reset_tokens r join users u on u.id = r.user_id
        where r.id = :id and ((:notice and r.used_at is not null)
           or (not :notice and r.used_at is null and r.expires_at > :now and u.email_verified and u.enabled)))
        """, nativeQuery = true)
    boolean resetDeliverable(@Param("id") UUID id, @Param("notice") boolean notice, @Param("now") Instant now);
}
