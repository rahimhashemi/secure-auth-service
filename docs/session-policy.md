# Session policy and failure-only throttling

## Refresh state transitions

Rotation checks expiry before revoked/replaced state. Expired history always returns
401 without revoking another token. Unexpired reuse revokes only the matching family
under the existing pessimistic user lock; revocation commits on the typed exception.
The audit retains userId, familyId and reason. Logout-all still explicitly revokes all
refresh families. Access JWTs remain valid until their configured expiry.

A retry grace period is deliberately omitted: replaying an opaque refresh token
cannot distinguish its owner from a thief. The service does not persist plaintext
successor tokens and cannot safely return the same successor. Serialize client refresh
requests. A lost response followed by retry can still revoke that family's successor.

## Login failure budget

Redis atomically checks a normalized-account failure bucket before credential work.
Unknown users, disabled users and wrong passwords all record a failure; a successful
login does not consume or reset the bucket. Per-IP counters continue counting every
request. Account buckets use a v2 namespace so older all-attempt counts are not
misinterpreted as failures during deployment. Old buckets expire naturally.

Counting after BCrypt means simultaneous admissions can overshoot the account limit.
This tradeoff avoids charging successful logins and keeps no distributed reservation
or lease state. It does not eliminate targeted temporary login denial: an attacker can
still fill a victim's failure bucket. There is no persistent account lock; rejections
and failures at capacity do not extend the TTL. Redis failure returns 503.

## Cleanup architecture

A scheduled coordinator fixes the retention cutoff once per run. It calls a separate
transactional batch service, stopping on a partial batch or configured count/runtime
cap. Each delete commits independently, so a later failure leaves earlier progress
committed and avoids one long transaction. The time budget is checked between batches;
it cannot preempt a blocked SQL statement.

## Validation

Integration coverage uses real PostgreSQL and Redis for family isolation, expired
reuse, concurrent rotation, failure-only account limits, and multiple cleanup batches.
Unit tests check cleanup batch caps and stop conditions. CI runs Maven verify on Java
17 and 21. See the pull request for the final run and test count.
