# Authentication routing and audit repair

## Reproduction

Regression-only commit on this branch was tested with the real embedded server on
Java 17 and 21 (Actions run 41712817719). All six new regressions failed against the
previous implementation: encoded register/login/refresh did not share the IP budget,
encoded login with stale Bearer returned 401, and unsupported method/media returned
500 instead of 405/415. Encoded requests were proved to reach MVC bean validation;
the tests do not double-encode the percent escape or rely only on MockMvc.

## Implementation

One AuthEndpointMatcher uses Spring Security's default PathPatternRequestMatcher
for both rate limiting and public-authentication JWT bypass. It matches the same
POST endpoints under MVC's default parser, without hand-decoding URLs. Custom MVC
parser/servlet-path configuration must be mirrored in this matcher if introduced.

GlobalExceptionHandler delegates framework exceptions to ResponseEntityExceptionHandler,
overrides the common response body with ApiError, and preserves HTTP status/headers
(including Allow and supported media types). Domain failures retain their explicit
handlers. Unexpected exceptions still receive a generic 500 with an error ID.
A shared ApiErrorWriter produces code, message, timestamp and path for JWT/rate-limit
filters and security entry-point failures, instead of ad-hoc JSON shapes.

EmailNormalizer is shared by register/login; findByEmail uses equality on the
canonical stored address, enabling an indexed lookup. This does not promise PostgreSQL
will always select an index on small tables. V3 rejects pre-existing noncanonical
emails without rewriting or merging identities. Inspect and reconcile such legacy
data before migration; external writers must maintain the normalization invariant.
V1/V2 remain unchanged. Database locale/Unicode normalization differences should be
reviewed if internationalized email addresses are introduced.

Refresh failures carry a typed reason, userId and familyId when known. Audit does
not classify errors by message strings; reuse events retain the affected user and
family. No raw refresh/access token is logged. This PR does not change the existing
all-session reuse policy; that behavioral change is isolated in a follow-up.

## Configuration change

APP_RATE_LIMIT_ACCOUNT_KEY is now required and independent of APP_REFRESH_PEPPER.
Generate a separate random secret, distribute it consistently to all app instances
and do not commit it. Rotating the account key resets account rate-limit buckets
without invalidating refresh tokens. Tests use explicitly configured test-only keys.

## Verification

Run `mvn clean verify` with Docker available. Regression coverage includes encoded
and canonical paths sharing counters, stale-Bearer recovery, MVC status/header
preservation, uniform filter error JSON, normalized login, audit attribution, and
refusal to adopt noncanonical legacy email rows. No external database is accessed.
