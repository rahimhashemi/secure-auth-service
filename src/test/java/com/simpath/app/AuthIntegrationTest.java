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
import org.springframework.test.annotation.DirtiesContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import org.testcontainers.containers.PostgreSQLContainer;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest(properties = {
    "app.jwt.secret=test-only-key-with-at-least-thirty-two-characters",
    "app.refresh-token.pepper=test-only-pepper",
    "app.rate-limit.login-limit=3", "app.rate-limit.refresh-limit=2",
    "spring.jpa.hibernate.ddl-auto=create-drop", "spring.jpa.show-sql=false"
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
        PostgreSQLContainer<?> postgres() {
            return new PostgreSQLContainer<>("postgres:16-alpine");
        }

        @Bean
        @ServiceConnection(name = "redis")
        GenericContainer<?> redis() {
            return new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                    .withExposedPorts(6379);
        }
    }

    @Autowired MockMvc mvc;
    @Autowired AuthService auth;
    @Autowired RefreshTokenService refresh;
    @Autowired RefreshTokenRepository tokens;
    @Autowired UserRepository users;
    @Autowired AuditEventRepository audit;
    UUID userId;
    @BeforeEach void setup() {
        tokens.deleteAll(); audit.deleteAll(); users.deleteAll();
        auth.register(new RegisterRequest("rahim@example.com", "Passw0rd!"));
        userId = users.findByEmailIgnoreCase("rahim@example.com").orElseThrow().getId();
    }
    AuthResponse login() { return auth.login(new LoginRequest("rahim@example.com", "Passw0rd!"), "test", "127.0.0.1"); }
    @Test void expiredRefreshIsRejectedWithoutCreatingSuccessor() {
        AuthResponse session = login();
        RefreshToken token = tokens.findByUserId(userId).get(0);
        token.setExpiresAt(Instant.now().minusSeconds(1)); tokens.saveAndFlush(token);
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(session.refreshToken()), "test", "ip"))
            .isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(tokens.findByUserId(userId)).hasSize(1);
    }
    @Test void reuseRevokesAllSessionsAndPersistsAuditAfterException() {
        AuthResponse session = login(); login();
        AuthResponse next = auth.refresh(new RefreshRequest(session.refreshToken()), "test", "ip");
        assertThat(next.refreshToken()).isNotEqualTo(session.refreshToken());
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(session.refreshToken()), "test", "ip"))
            .isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(tokens.findByUserId(userId)).allMatch(t -> t.getRevokedAt() != null);
        assertThat(audit.findAll()).anyMatch(e -> "REFRESH_REUSE".equals(e.getType()));
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(next.refreshToken()), "test", "ip"))
            .isInstanceOf(InvalidRefreshTokenException.class);
    }
    @Test void failedLoginAuditSurvivesRollback() {
        assertThatThrownBy(() -> auth.login(new LoginRequest("rahim@example.com", "wrong"), "test", "ip"))
            .isInstanceOf(IllegalArgumentException.class);
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
                    .andExpect(status().isBadRequest());
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
}

