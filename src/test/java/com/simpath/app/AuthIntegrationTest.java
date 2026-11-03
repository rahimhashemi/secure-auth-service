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
        tokens.deleteAll(); audit.deleteAll(); users.deleteAll();
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
        assertThat(flyway.info().current().getVersion().getVersion()).isEqualTo("3");
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

}





