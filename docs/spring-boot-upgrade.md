# Spring Boot platform upgrade

## Target and approach

The application moves from Spring Boot 3.3.2 through a tested 3.5.16 checkpoint to
Spring Boot 4.1.2. springdoc moves from 2.6.0 through 2.10.0 to 3.2.0. These final
versions were verified against official release metadata during this upgrade.

Boot 4.0 and 4.1 are maintained at the time of this change. The 4.0 line is an
alternative with a smaller minor-version step; 4.1.2 is selected as the newer stable
line. Milestone/RC releases are not used. Java 17 remains the compilation/runtime
minimum; CI verifies the suite on Java 17 and Java 21.

The architecture stays Servlet MVC -> services -> JPA/PostgreSQL, with Redis-based
rate limiting. There is no WebFlux rewrite, new migration, table change, token
revocation design change or new endpoint in this PR.

## Dependency and integration changes

- Use `spring-boot-starter-webmvc` and `spring-boot-starter-flyway` for Boot 4's modular
  auto-configuration. Keep PostgreSQL's Flyway module explicitly declared.
- Use `spring-boot-starter-webmvc-test` and `spring-boot-starter-security-test`, and
  the new `org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc`.
- Let Boot manage Spring Framework, Security, Hibernate, Flyway, Jackson, Lombok,
  Redis/Lettuce, Testcontainers and test-framework versions. Do not retain the old
  Testcontainers 1.x override or a separate Lombok version.
- Testcontainers 2 modules use `testcontainers-postgresql` and
  `testcontainers-junit-jupiter`; use its non-generic PostgreSQLContainer class in
  `org.testcontainers.postgresql`. Spring still manages container beans so they stop
  after database/Redis clients are destroyed.
- HTTP JSON uses Boot's Jackson 3 mapper. Set `spring.jackson.use-jackson2-defaults`
  to preserve existing JSON defaults while adopting the actual Jackson 3 runtime.
  JJWT 0.11.5 is deliberately not redesigned in this migration. Its `jjwt-jackson`
  adapter uses Jackson 2 in isolation; Boot still manages Jackson 2 dependencies.
  No deprecated Boot Jackson 2 auto-configuration module is added. Successful
  login/protected-resource/refresh/logout HTTP tests verify the two JSON stacks
  work together. A JJWT API upgrade remains a separate dependency-maintenance task.
- Return 404 for absent MVC resources instead of allowing the generic exception
  handler to turn disabled documentation endpoints into 500 responses.

## Compatibility and validation

Existing V1/V2 migration files remain byte-for-byte unchanged. Flyway migrations
and Hibernate validation run against PostgreSQL Testcontainers; no baseline, repair
or destructive schema operation is introduced. PostgreSQL 16 and Redis 7 test
images and the Java 17 Docker runtime are retained.

The pre-existing 47 tests are retained. Additional tests cover:

1. Documentation remaining disabled by default.
2. Real embedded-server OpenAPI generation when explicitly enabled.
3. Swagger UI resources when explicitly enabled.
4. Real HTTP login, protected `/me`, refresh, logout and rejected post-logout refresh,
   including JSON field names and ISO-8601 error timestamps.

CI runs Maven `verify` on both supported project JDKs (17 and 21). A successful
result validates the tested contracts, not every possible deployment integration or
all dependency vulnerabilities. Review dependency alerts and deployment-specific
TLS/proxy settings independently.

## Local verification

With Docker running:

```bash
git fetch origin
git switch feature/spring-boot-upgrade
git pull --ff-only
mvn -U clean verify
```

For normal application startup, provide database credentials and JWT/pepper secrets
as documented in the README. Existing access tokens are not intentionally revoked
by this upgrade if the configured signing key/issuer and storage are retained.
Swagger remains opt-in. No database reset is required.

## Sources

- https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-4.0-Migration-Guide
- https://docs.spring.io/spring-boot/appendix/dependency-versions/coordinates.html
- https://springdoc.org/
