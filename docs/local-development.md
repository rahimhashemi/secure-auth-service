# Local development and troubleshooting

The recommended host test JDKs are **17 and 21**, matching CI. Running the application
with Compose uses the Java 17 builder/runtime images in the Dockerfile. Compose,
host Maven and Testcontainers each have their own configuration; diagnose the phase
that failed.

## Environment and database recovery

The [README initializer](../README.md#first-setup-persist-the-secrets) creates `.env`
once and reuses any of the five original hex secrets still exported in that terminal.
It preserves an existing file. For custom values, copy `.env.example` into a **new**
file and fill it with the original configuration, following
[Compose dotenv quoting rules](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/).

| Setting | Generated format | Purpose |
| --- | --- | --- |
| `POSTGRES_PASSWORD` | 24 random bytes as 48 hex characters | Database role password |
| `APP_JWT_SECRET` | 32 random bytes as 64 hex characters | HS256 signing; application requires at least 32 UTF-8 bytes |
| `APP_REFRESH_PEPPER` | 32 random bytes as 64 hex characters | Hashing refresh tokens |
| `APP_RATE_LIMIT_ACCOUNT_KEY` | 32 random bytes as 64 hex characters | Account rate-limit HMACs |
| `APP_MAIL_OUTBOX_KEY` | Exactly 32 bytes as 64 hex characters | AES-GCM outbox encryption |

An `export` exists in that shell and its child processes. Opening another terminal
does not recreate it. Compose loads `.env` automatically but shell exports take
precedence. Even `docker compose exec postgres ...` first interpolates the complete
Compose model, so a missing application secret can block a PostgreSQL-only command.

Check required values without printing them:

```bash
docker compose config --quiet
```

If the original exports are lost but the old app container still exists, inspect
its environment **locally** in Docker Desktop and recover the original values.
The four `APP_...` names are unchanged; the app container's
`SPRING_DATASOURCE_PASSWORD` maps to `POSTGRES_PASSWORD` in `.env`.
Use `docker ps -a` if you need to locate a stopped container. Inspection output
contains credentials; keep it out of shared logs. Preserve the existing containers
and data while recovering the settings.

### PostgreSQL password mismatch

For `FATAL: password authentication failed for user "auth"`, compare the saved
database password with the value used when the data directory was initialized.
The official PostgreSQL image uses `POSTGRES_PASSWORD` during initial creation;
changing the environment later does not change the existing role password.
See the [image documentation](https://hub.docker.com/_/postgres).

Prefer recovering the original values. If you deliberately need to align this local
database role with the password currently configured in Compose, these commands
preserve the database data. They rely on the official image's local Unix-socket
authentication inside the PostgreSQL container:

```bash
docker compose up -d --wait postgres
docker compose exec -T postgres sh -eu -c '
  printf "%s\n%s\n" "$POSTGRES_PASSWORD" "$POSTGRES_PASSWORD" |
    psql -X -w -U auth -d authdb -v ON_ERROR_STOP=1 -c "\password auth"
'
```

Expect `ALTER ROLE`. Then start the services with `docker compose up -d`.
Keep the matching password in `.env`. Do not delete database volumes as a shortcut
for a credential mismatch.

## Docker Desktop on Linux

A missing `~/.docker/desktop/docker.sock` means the selected Desktop daemon is not
available at that socket. Start it as your desktop user:

```bash
systemctl --user start docker-desktop
```

Wait for Docker Desktop to report **Running**, then:

```bash
docker context use desktop-linux
docker info
```

The `Server` section must be available. If Desktop fails to start:

```bash
journalctl --user -u docker-desktop -n 60 --no-pager
```

See [Docker Desktop on Ubuntu](https://docs.docker.com/desktop/setup/install/linux/ubuntu/).
Desktop's `desktop-linux` and the system Engine's `default` context have separate
images, containers and volumes. Select the daemon containing this project's data.

## Registry access

An HTTP 403 while pulling image metadata occurs before application startup. Check
the registry hostname in the error and the Docker daemon's network/proxy settings.
Do not interpret it as an authentication test failure.

Docker publishes official images on
[Amazon ECR Public](https://aws.amazon.com/blogs/containers/docker-official-images-now-available-on-amazon-elastic-container-registry-public/).
For a Docker Hub access failure, the corresponding alternative names are:

| Docker Hub reference | ECR Public reference |
| --- | --- |
| `maven:3.9.9-eclipse-temurin-17` | `public.ecr.aws/docker/library/maven:3.9.9-eclipse-temurin-17` |
| `eclipse-temurin:17-jre` | `public.ecr.aws/docker/library/eclipse-temurin:17-jre` |
| `postgres:16` | `public.ecr.aws/docker/library/postgres:16` |
| `redis:7` | `public.ecr.aws/docker/library/redis:7` |

Check that the required tag is available and that your daemon can pull it before
changing the references. For the current Dockerfile/Compose defaults, replacements
are:

```bash
sed -i \
  -e 's|^FROM maven:|FROM public.ecr.aws/docker/library/maven:|' \
  -e 's|^FROM eclipse-temurin:|FROM public.ecr.aws/docker/library/eclipse-temurin:|' \
  Dockerfile

sed -i \
  -e 's|image: postgres:|image: public.ecr.aws/docker/library/postgres:|' \
  -e 's|image: redis:|image: public.ecr.aws/docker/library/redis:|' \
  compose.yaml
```

Mailpit also has an
[official GHCR mirror](https://mailpit.axllent.org/docs/install/docker/).
For example, `ghcr.io/axllent/mailpit:v1.34.0` is a published stable image.
Replacing the repository's `axllent/mailpit:v1.20` with this example also upgrades
Mailpit's version; review the local diff. The browser inbox remains on port 8025.

**Testcontainers images are independent.** The tests still reference Docker Hub,
including `axllent/mailpit:v1.20`. A successful Compose build does not prove every
test image can be pulled. Any registry substitution must account for PostgreSQL,
Redis, Mailpit and Ryuk. An ECR `docker/library/` prefix alone will not provide
arbitrary third-party images. See
[Testcontainers image substitution](https://java.testcontainers.org/features/image_name_substitution/).

## Lombok compilation

For missing generated methods such as `AuditEvent.setType` or `setUserId`, first
check the actual Maven JDK:

```bash
bash mvnw -v
```

`release 17` in compiler output describes the bytecode/API target. It does not mean
Maven itself runs on JDK 17. `AuditEvent` has `@Getter` and `@Setter`, but the
current POM does not explicitly list Lombok as an annotation processor.

Since JDK 23, annotation processing requires explicit activation. Use the CI-tested
JDK 17/21, or isolate the processor issue with this diagnostic command:

```bash
bash mvnw -B -Dmaven.compiler.proc=full clean test-compile
```

This compiles application and test code without starting Testcontainers. If that
succeeds, keep the diagnostic flag for the full verification:

```bash
DOCKER_HOST="unix://$HOME/.docker/desktop/docker.sock" \
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
bash mvnw -B -Dmaven.compiler.proc=full verify
```

Those socket variables apply to Linux Docker Desktop. For the system Docker Engine,
use the normal test command from the README.

The durable build fix is explicitly configuring Lombok in the Maven compiler's
`annotationProcessorPaths`, using the Boot-managed Lombok version. This documentation
change does not apply that POM fix. Confirm that the Lombok version supports your
chosen newer JDK as well. See [Lombok Maven setup](https://projectlombok.org/setup/maven)
and [Maven compiler processing options](https://maven.apache.org/plugins/maven-compiler-plugin/compile-mojo.html).

## Email verification

Mailpit is the local inbox at **http://localhost:8025**, opened on the computer
running Docker. Compose points the application at `mailpit:1025`. A Gmail address
in the registration body still appears in Mailpit when using these defaults.

Use the **same email address** in registration, login and verification requests.
Use a fresh email for a repeatable signup scenario. Duplicate registration keeps
the original account/password and does not queue another verification message.

1. Register a valid password such as `Correct-Horse-123!`.
2. Allow at least one mail worker poll, normally about ten seconds.
3. Open **Verify your email - Secure Auth Service** for that exact recipient in Mailpit.
4. Follow the link and press **Confirm email** explicitly.
5. Expect HTTP **204** with an empty body from confirmation, then sign in.

The link contains `verify-email.html#token=` followed by a **43-character** token.
For direct Swagger/API confirmation, send just that value as JSON `token`.
The confirmation page removes the URL fragment immediately on load; copy from the
email itself and reopen the original email link after refreshing the page.

`INVALID_CREDENTIALS` is deliberately generic: unknown account, wrong password,
disabled account and unverified email all receive it.
`INVALID_VERIFICATION_TOKEN` also covers wrong format, unknown token, expiry,
prior use, a disabled owner or an owner already verified by another link.
A token hash stored in the database cannot be used as the plaintext email token.

For an existing enabled, unverified account, request another email with
`POST /auth/email-verification/request` and an `email` field. A generic **202**
does not prove delivery or account eligibility. A per-user cooldown prevents another
email within one minute; the normalized-account budget is three requests per hour,
and separate IP budgets also apply. Allow the previous request to finish rather
than repeatedly requesting links.

Both earlier and newer unexpired verification links remain usable until the first
successful confirmation. After that, further confirmations are rejected. Tokens
expire after 30 minutes. Check the exact recipient, delivery state and token
timestamps if a fresh link still fails.

To deliver to an external inbox, configure `SMTP_HOST`, `SMTP_PORT`,
`SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_AUTH` and `SMTP_STARTTLS` for your provider,
plus `APP_MAIL_FROM` and an HTTPS `APP_VERIFICATION_PUBLIC_URL`.

## Manual functional checks

Start with a fresh email, record access/refresh tokens from login and use
Swagger's **Authorize** for protected calls.

| Action | Expected result |
| --- | --- |
| Register with a valid password | 200; account unverified; verification email queued |
| Login before verification | 401 `INVALID_CREDENTIALS` |
| Confirm the email token | 204 |
| Login after confirmation | 200 with access/refresh tokens |
| Call `GET /me` with the access token | 200 with the expected user's id and email |
| Refresh once with R1 | 200 with new access token and R2 |
| Reuse R1 in a separate reuse-detection check | 401; that session family is revoked; its access token and R2 fail |
| Request password recovery for an enabled, verified account | 202; email appears in Mailpit |
| Follow the recovery email link, set a valid new password | 204 from `POST /auth/password-reset/confirm` |
| Use the pre-reset access/refresh tokens | 401 |
| Login with the old password, then with the new password | 401, then 200 |
| Logout with the currently active refresh token | 200; the session's access/refresh tokens subsequently fail |
| List sessions and revoke one of your other device sessions | List returns 200; deletion returns 204; that device loses access |

After a reuse-detection test, log in again to obtain a live session before checking
password reset or logout. For password reset, keep a live session before requesting
the link so that its revocation can be tested. Reset links expire after 15 minutes,
are single-use and distinct from email verification links. Confirmation uses
`token` and `newPassword`; request uses `email`.

TOTP MFA, MFA recovery codes and Step-Up sessions are still planned; a branch name
alone does not add their endpoints or tests.

## Application startup failures

The summary `Unable to start web server`, `jwtAuthFilter` or a missing
`entityManagerFactory` can be the outer layer of a nested initialization failure.
Read through the **last `Caused by`** and the database logs before assigning a cause:

```bash
docker compose logs --no-color --tail=350 app postgres
```

PostgreSQL authentication failure, Flyway validation failure and schema problems need
different repairs. Keep the underlying error when sharing a startup report; a
truncated dependency-injection stack alone does not identify the root cause.
