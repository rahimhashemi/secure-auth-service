package com.simpath.app;

import com.simpath.app.auth.dto.*;
import com.simpath.app.auth.service.AuthService;
import com.simpath.app.audit.AuditEventRepository;
import com.simpath.app.common.InvalidRefreshTokenException;
import com.simpath.app.token.refresh.entity.RefreshToken;
import com.simpath.app.token.refresh.repo.RefreshTokenRepository;
import com.simpath.app.token.refresh.service.RefreshTokenService;
import com.simpath.app.user.entity.User;
import com.simpath.app.user.repo.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.flywaydb.core.Flyway;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import org.testcontainers.postgresql.PostgreSQLContainer;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest(properties = {
    "app.jwt.secret=test-only-key-with-at-least-thirty-two-characters",
    "spring.datasource.username=test", "spring.datasource.password=test",
    "app.refresh-token.pepper=test-only-pepper",
        "app.rate-limit.account-key=test-only-account-key",
    "app.token-cleanup.enabled=true", "app.token-cleanup.cron=-",
    "app.token-cleanup.batch-size=1", "app.token-cleanup.max-batches=2", "app.rate-limit.account-limit=3",
    "app.rate-limit.login-limit=3", "app.rate-limit.refresh-limit=2",
    "spring.jpa.show-sql=false"
})
@Import(AuthIntegrationTest.Containers.class)
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class AuthIntegrationTest {
    @TestConfiguration(proxyBeanMethods = false)
    static class Containers {
        // Spring starts container beans first and stops them after dependent clients.
        @Bean
        @ServiceConnection
        PostgreSQLContainer postgres() {
            return new PostgreSQLContainer("postgres:16-alpine");
        }

        @Bean
        @ServiceConnection(name = "redis")
        GenericContainer<?> redis() {
            return new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                    .withExposedPorts(6379);
        }
    }

    @Autowired MockMvc mvc;
    @Autowired com.simpath.app.session.SessionRepository sessions;
    @Autowired com.simpath.app.session.SessionService sessionService;
    @Autowired javax.crypto.SecretKey jwtKey;
    @Autowired org.springframework.core.env.Environment environment;
    @Autowired com.simpath.app.token.refresh.service.TokenCleanupService cleanup;
    @Autowired org.springframework.data.redis.core.StringRedisTemplate redis;
    @Autowired Flyway flyway;
    @Autowired JdbcTemplate jdbc;
    @Autowired AuthService auth;
    @Autowired RefreshTokenService refresh;
    @Autowired RefreshTokenRepository tokens;
    @Autowired UserRepository users;
    @Autowired AuditEventRepository audit;
    UUID userId;
    @BeforeEach void setup() {
        try (org.springframework.data.redis.connection.RedisConnection connection = redis.getConnectionFactory().getConnection()) {
            connection.serverCommands().flushDb();
        }
        tokens.deleteAll(); sessions.deleteAll(); audit.deleteAll(); users.deleteAll();
        auth.register(new RegisterRequest("rahim@example.com", "Correct-Horse-123!"));
        userId = users.findByEmail("rahim@example.com").orElseThrow().getId();
    }
    AuthResponse login() { return auth.login(new LoginRequest("rahim@example.com", "Correct-Horse-123!"), "test", "127.0.0.1"); }
    @Test void expiredRefreshIsRejectedWithoutCreatingSuccessor() {
        AuthResponse session = login();
        RefreshToken token = tokens.findByUserId(userId).get(0);
        token.setExpiresAt(Instant.now().minusSeconds(1)); tokens.saveAndFlush(token);
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(session.refreshToken()), "test", "ip"))
            .isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(tokens.findByUserId(userId)).hasSize(1);
    }
    @Test void reuseRevokesOnlyItsFamilyAndPersistsAuditAfterException() {
        AuthResponse session = login(); AuthResponse otherDevice = login();
        AuthResponse next = auth.refresh(new RefreshRequest(session.refreshToken()), "test", "ip");
        assertThat(next.refreshToken()).isNotEqualTo(session.refreshToken());
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(session.refreshToken()), "test", "ip"))
            .isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(tokens.findByUserId(userId).stream().filter(t -> t.getRevokedAt() != null)).hasSize(2);
        assertThat(refresh.getUserIdFromRefresh(otherDevice.refreshToken())).isEqualTo(userId);
        assertThat(audit.findAll()).anyMatch(e -> "REFRESH_REUSE".equals(e.getType())
                && userId.equals(e.getUserId()) && e.getDetail().contains("reason=REUSE;familyId="));
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(next.refreshToken()), "test", "ip"))
            .isInstanceOf(InvalidRefreshTokenException.class);
    }
    @Test void failedLoginAuditSurvivesRollback() {
        assertThatThrownBy(() -> auth.login(new LoginRequest("rahim@example.com", "wrong"), "test", "ip"))
            .isInstanceOf(com.simpath.app.common.InvalidCredentialsException.class);
        assertThat(audit.findAll()).anyMatch(e -> "LOGIN_FAIL".equals(e.getType()));
    }
    @Test void disabledUserCannotRefresh() {
        AuthResponse session = login();
        User user = users.findById(userId).orElseThrow(); user.setEnabled(false); users.saveAndFlush(user);
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(session.refreshToken()), "test", "ip"))
            .isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(tokens.findByUserId(userId)).hasSize(1);
    }
    @Test void concurrentRotationCreatesOnlyOneSuccessor() throws Exception {
        AuthResponse session = login();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        Callable<Boolean> rotate = () -> {
            ready.countDown();
            if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("start timeout");
            try { auth.refresh(new RefreshRequest(session.refreshToken()), "test", "ip"); return true; }
            catch (InvalidRefreshTokenException expected) { return false; }
        };
        try {
            Future<Boolean> first = executor.submit(rotate);
            Future<Boolean> second = executor.submit(rotate);
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue(); start.countDown();
            assertThat(first.get(20, TimeUnit.SECONDS) ^ second.get(20, TimeUnit.SECONDS)).isTrue();
            assertThat(tokens.findByUserId(userId)).hasSize(2).allMatch(t -> t.getRevokedAt() != null);
        } finally { start.countDown(); executor.shutdownNow(); }
    }
    @Test void revokedTokenCannotLogoutAll() {
        AuthResponse old = login();
        AuthResponse next = auth.refresh(new RefreshRequest(old.refreshToken()), "test", "ip");
        assertThatThrownBy(() -> auth.logoutAll(new LogoutRequest(old.refreshToken()), "test", "ip"))
            .isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(refresh.getUserIdFromRefresh(next.refreshToken())).isEqualTo(userId);
    }

    @Test void loginHttpLimitIsAppliedExactlyOncePerRequest() throws Exception {
        String ip = "192.0.2.30";
        for (int i = 0; i < 3; i++) {
            mvc.perform(post("/auth/login").with(request -> { request.setRemoteAddr(ip); return request; })
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"email\":\"rahim@example.com\",\"password\":\"wrong\"}"))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/auth/login").with(request -> { request.setRemoteAddr(ip); return request; })
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.code").value("RATE_LIMIT_EXCEEDED"));
    }

    @Test void malformedRefreshConsumesCapacityButOtherAddressesAreIndependent() throws Exception {
        for (int i = 0; i < 2; i++) {
            mvc.perform(post("/auth/refresh").with(request -> { request.setRemoteAddr("192.0.2.31"); return request; })
                    .contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isBadRequest());
        }
        mvc.perform(post("/auth/refresh").with(request -> { request.setRemoteAddr("192.0.2.31"); return request; })
                .header("X-Forwarded-For", "198.51.100.1")
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isTooManyRequests());
        mvc.perform(post("/auth/refresh").with(request -> { request.setRemoteAddr("192.0.2.32"); return request; })
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test void applicationStartsAgainstFlywaySchemaWithoutHibernateCreatingTables() {
        assertThat(flyway.info().current().getVersion().getVersion()).isEqualTo("4");
        assertThat(flyway.info().pending()).isEmpty();
        assertThat(jdbc.queryForObject(
                "select count(*) from flyway_schema_history where version = '1' and success = true", Integer.class))
                .isEqualTo(1);
    }

    @Test void accountLimitAppliesAcrossDifferentAddresses() throws Exception {
        for (int i = 1; i <= 3; i++) {
            String ip = "192.0.2." + (100 + i);
            mvc.perform(post("/auth/login").with(request -> { request.setRemoteAddr(ip); return request; })
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"email\":\"rahim@example.com\",\"password\":\"wrong\"}"))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/auth/login").with(request -> { request.setRemoteAddr("192.0.2.110"); return request; })
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"rahim@example.com\",\"password\":\"wrong\"}"))
                .andExpect(status().isTooManyRequests()).andExpect(header().exists("Retry-After"));
    }
    @Test void registerRejectsWeakPasswordAndHidesDuplicates() throws Exception {
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"new@example.com\",\"password\":\"a\"}"))
                .andExpect(status().isBadRequest());
        String body = "{\"email\":\"new@example.com\",\"password\":\"Correct-Horse-123!\"}";
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isOk());
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isOk());
        assertThat(users.findByEmail("new@example.com")).isPresent();
    }
    @Test void registrationIsThrottledBeforePasswordHashing() throws Exception {
        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isBadRequest());
        }
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isTooManyRequests());
    }
    @Test void concurrentRegistrationCreatesOneUserWithoutServerError() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        Callable<Boolean> registration = () -> {
            if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("timeout");
            auth.register(new RegisterRequest("race@example.com", "Correct-Horse-123!")); return true;
        };
        try {
            Future<Boolean> first = executor.submit(registration);
            Future<Boolean> second = executor.submit(registration);
            start.countDown();
            assertThat(first.get(30, TimeUnit.SECONDS)).isTrue();
            assertThat(second.get(30, TimeUnit.SECONDS)).isTrue();
            assertThat(jdbc.queryForObject("select count(*) from users where email='race@example.com'", Integer.class)).isEqualTo(1);
        } finally { start.countDown(); executor.shutdownNow(); }
    }
    @Test void tokenHashUniquenessIsEnforcedByDatabase() {
        login();
        RefreshToken original = tokens.findByUserId(userId).get(0);
        RefreshToken duplicate = new RefreshToken();
        duplicate.setUserId(userId); duplicate.setFamilyId(java.util.UUID.randomUUID());
        duplicate.setTokenHash(original.getTokenHash());
        assertThatThrownBy(() -> tokens.saveAndFlush(duplicate))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }
    @Test void cleanupIsBoundedAndRetainsRecentHistory() {
        for (int i = 0; i < 5; i++) {
            RefreshToken token = new RefreshToken();
            token.setUserId(userId); token.setFamilyId(java.util.UUID.randomUUID());
            token.setTokenHash("cleanup-" + i);
            token.setExpiresAt(Instant.now().minus(i < 4 ? 60 : 5, java.time.temporal.ChronoUnit.DAYS));
            tokens.saveAndFlush(token);
        }
        cleanup.cleanup();
        assertThat(tokens.findByUserId(userId)).hasSize(3);
        cleanup.cleanup();
        assertThat(tokens.findByUserId(userId)).hasSize(1).allMatch(t -> "cleanup-4".equals(t.getTokenHash()));
    }

    @Test void apiDocumentationRemainsDisabledByDefault() throws Exception {
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/v3/api-docs"))
                .andExpect(status().isNotFound());
    }

    @Test void normalizedLoginUsesTheCanonicalStoredEmail() {
        AuthResponse response = auth.login(new LoginRequest("RAHIM@example.com", "Correct-Horse-123!"), "test", "ip");
        assertThat(response.accessToken()).isNotBlank();
    }
    @Test void expiredRotatedTokenCannotRevokeAnyLiveFamily() {
        AuthResponse old = login();
        AuthResponse successor = auth.refresh(new RefreshRequest(old.refreshToken()), "test", "ip");
        AuthResponse other = login();
        RefreshToken history = tokens.findByUserId(userId).stream()
                .filter(token -> token.getReplacedBy() != null).findFirst().orElseThrow();
        history.setExpiresAt(Instant.now().minusSeconds(1));
        tokens.saveAndFlush(history);
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(old.refreshToken()), "test", "ip"))
                .isInstanceOfSatisfying(InvalidRefreshTokenException.class,
                        error -> assertThat(error.getReason()).isEqualTo(InvalidRefreshTokenException.Reason.EXPIRED));
        assertThat(refresh.getUserIdFromRefresh(successor.refreshToken())).isEqualTo(userId);
        assertThat(refresh.getUserIdFromRefresh(other.refreshToken())).isEqualTo(userId);
        assertThat(audit.findAll()).noneMatch(event -> "REFRESH_REUSE".equals(event.getType()));
    }

    @Test void successfulLoginsDoNotConsumeOrResetFailureBudget() {
        for (int i = 0; i < 4; i++) assertThat(login().refreshToken()).isNotBlank();
        for (int i = 0; i < 2; i++) {
            assertThatThrownBy(() -> auth.login(new LoginRequest("rahim@example.com", "wrong"), "test", "ip"))
                    .isInstanceOf(com.simpath.app.common.InvalidCredentialsException.class);
        }
        assertThat(login().refreshToken()).isNotBlank();
        assertThatThrownBy(() -> auth.login(new LoginRequest("rahim@example.com", "wrong"), "test", "ip"))
                .isInstanceOf(com.simpath.app.common.InvalidCredentialsException.class);
        assertThatThrownBy(this::login).isInstanceOf(com.simpath.app.common.RateLimitExceededException.class);
    }

    private UUID sessionId(AuthResponse response) {
        return UUID.fromString(io.jsonwebtoken.Jwts.parserBuilder().setSigningKey(jwtKey).build()
                .parseClaimsJws(response.accessToken()).getBody().get("sid", String.class));
    }

    private org.springframework.test.web.servlet.ResultActions me(AuthResponse response) throws Exception {
        return mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/me")
                .header("Authorization", "Bearer " + response.accessToken()));
    }

    @Test void logoutImmediatelyInvalidatesAccessAndRefreshForThatSession() throws Exception {
        AuthResponse current = login();
        AuthResponse other = login();
        me(current).andExpect(status().isOk());
        auth.logout(new LogoutRequest(current.refreshToken()), "test", "ip");
        me(current).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_TOKEN"));
        me(other).andExpect(status().isOk());
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(current.refreshToken()), "test", "ip"))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test void logoutAllAndDisablementInvalidateAccessTokens() throws Exception {
        AuthResponse first = login();
        AuthResponse second = login();
        auth.logoutAll(new LogoutRequest(first.refreshToken()), "test", "ip");
        me(first).andExpect(status().isUnauthorized());
        me(second).andExpect(status().isUnauthorized());
        AuthResponse newSession = login();
        User user = users.findById(userId).orElseThrow();
        user.setEnabled(false); users.saveAndFlush(user);
        me(newSession).andExpect(status().isUnauthorized());
    }

    @Test void refreshKeepsTheSessionAndReuseInvalidatesItsAccessTokensOnly() throws Exception {
        AuthResponse first = login();
        AuthResponse other = login();
        AuthResponse rotated = auth.refresh(new RefreshRequest(first.refreshToken()), "test", "ip");
        assertThat(sessionId(rotated)).isEqualTo(sessionId(first));
        me(first).andExpect(status().isOk());
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(first.refreshToken()), "test", "ip"))
                .isInstanceOf(InvalidRefreshTokenException.class);
        me(first).andExpect(status().isUnauthorized());
        me(rotated).andExpect(status().isUnauthorized());
        me(other).andExpect(status().isOk());
    }

    @Test void sessionListIsPaginatedAndCannotExposeOtherUsers() throws Exception {
        AuthResponse first = login();
        login();
        auth.register(new RegisterRequest("other@example.com", "Correct-Horse-123!"));
        AuthResponse outsider = auth.login(new LoginRequest("other@example.com", "Correct-Horse-123!"), "outsider", "ip");
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/sessions")
                .header("Authorization", "Bearer " + first.accessToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[?(@.current == true)].id").value(sessionId(first).toString()))
                .andExpect(jsonPath("$[0].tokenHash").doesNotExist());
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/sessions?size=1&page=1")
                .header("Authorization", "Bearer " + first.accessToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1));
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/sessions?size=101")
                .header("Authorization", "Bearer " + first.accessToken())).andExpect(status().isBadRequest());
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/sessions/" + sessionId(outsider))
                .header("Authorization", "Bearer " + first.accessToken())).andExpect(status().isNoContent());
        me(outsider).andExpect(status().isOk());
    }

    @Test void revokeOthersPreservesCallerAndBlocksOtherSessionsAndTheirRefresh() throws Exception {
        AuthResponse first = login();
        AuthResponse other = login();
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/sessions/others")
                .header("Authorization", "Bearer " + first.accessToken())).andExpect(status().isNoContent());
        me(first).andExpect(status().isOk());
        me(other).andExpect(status().isUnauthorized());
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(other.refreshToken()), "test", "ip"))
                .isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(audit.findAll()).anyMatch(event -> "SESSION_REVOKE_OTHERS".equals(event.getType()));
    }

    @Test void revokeOneSessionIsIdempotentAndCanRevokeCaller() throws Exception {
        AuthResponse first = login();
        AuthResponse other = login();
        for (int i = 0; i < 2; i++) {
            mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/sessions/" + sessionId(other))
                    .header("Authorization", "Bearer " + first.accessToken())).andExpect(status().isNoContent());
        }
        me(other).andExpect(status().isUnauthorized());
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/sessions/" + sessionId(first))
                .header("Authorization", "Bearer " + first.accessToken())).andExpect(status().isNoContent());
        me(first).andExpect(status().isUnauthorized());
    }

    @Test void expiredSessionRejectsBothAccessAndRefresh() throws Exception {
        AuthResponse first = login();
        com.simpath.app.session.AuthSession session = sessions.findById(sessionId(first)).orElseThrow();
        session.setExpiresAt(Instant.now().minusSeconds(1)); sessions.saveAndFlush(session);
        me(first).andExpect(status().isUnauthorized());
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(first.refreshToken()), "test", "ip"))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test void legacyAndMismatchedSessionClaimsCannotAuthenticate() throws Exception {
        AuthResponse first = login();
        String issuer = environment.getRequiredProperty("app.jwt.issuer");
        String legacy = io.jsonwebtoken.Jwts.builder().setIssuer(issuer).setSubject(userId.toString())
                .setExpiration(java.util.Date.from(Instant.now().plusSeconds(600))).signWith(jwtKey).compact();
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/me")
                .header("Authorization", "Bearer " + legacy)).andExpect(status().isUnauthorized());
        String wrongOwner = io.jsonwebtoken.Jwts.builder().setIssuer(issuer).setSubject(UUID.randomUUID().toString())
                .claim("sid", sessionId(first).toString())
                .setExpiration(java.util.Date.from(Instant.now().plusSeconds(600))).signWith(jwtKey).compact();
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/me")
                .header("Authorization", "Bearer " + wrongOwner)).andExpect(status().isUnauthorized());
    }

    @Test void activityTimestampIsUpdatedWithoutWritingOnEveryRequest() throws Exception {
        AuthResponse first = login();
        com.simpath.app.session.AuthSession session = sessions.findById(sessionId(first)).orElseThrow();
        session.setLastSeenAt(Instant.now().minusSeconds(120)); sessions.saveAndFlush(session);
        me(first).andExpect(status().isOk());
        Instant touched = sessions.findById(session.getId()).orElseThrow().getLastSeenAt();
        assertThat(touched).isAfter(Instant.now().minusSeconds(10));
        me(first).andExpect(status().isOk());
        assertThat(sessions.findById(session.getId()).orElseThrow().getLastSeenAt()).isEqualTo(touched);
    }

    @Test void concurrentRefreshAndSessionRevocationCannotResurrectSession() throws Exception {
        AuthResponse target = login();
        AuthResponse caller = login();
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Future<AuthResponse> rotation = executor.submit(() -> {
                ready.countDown();
                if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("timeout");
                try { return auth.refresh(new RefreshRequest(target.refreshToken()), "test", "ip"); }
                catch (InvalidRefreshTokenException expected) { return null; }
            });
            Future<?> revocation = executor.submit(() -> {
                ready.countDown();
                try { if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("timeout"); }
                catch (InterruptedException ex) { throw new RuntimeException(ex); }
                sessionService.revokeManaged(userId, sessionId(caller), sessionId(target));
            });
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue(); start.countDown();
            AuthResponse successor = rotation.get(30, TimeUnit.SECONDS);
            revocation.get(30, TimeUnit.SECONDS);
            me(target).andExpect(status().isUnauthorized());
            if (successor != null) me(successor).andExpect(status().isUnauthorized());
            assertThat(tokens.findByUserIdAndFamilyId(userId, sessionId(target)))
                    .allMatch(token -> token.getRevokedAt() != null);
            me(caller).andExpect(status().isOk());
        } finally { start.countDown(); executor.shutdownNow(); }
    }

    @Test void cleanupDrainsOldSessionsAndKeepsRecentSessionHistory() {
        AuthResponse first = login();
        AuthResponse second = login();
        AuthResponse recent = login();
        for (UUID id : java.util.List.of(sessionId(first), sessionId(second))) {
            com.simpath.app.session.AuthSession session = sessions.findById(id).orElseThrow();
            session.setExpiresAt(Instant.now().minus(60, java.time.temporal.ChronoUnit.DAYS));
            sessions.saveAndFlush(session);
        }
        cleanup.cleanup();
        assertThat(sessions.findAll()).extracting(com.simpath.app.session.AuthSession::getId).containsExactly(sessionId(recent));
    }

}





