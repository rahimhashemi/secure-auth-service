package com.simpath.app.security;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.*;

@Testcontainers
class RateLimitRedisTest {
    @Container static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);
    private static LettuceConnectionFactory firstFactory;
    private static LettuceConnectionFactory secondFactory;
    private static StringRedisTemplate first;
    private static StringRedisTemplate second;

    @BeforeAll static void connect() {
        firstFactory = new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
        firstFactory.afterPropertiesSet();
        secondFactory = new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
        secondFactory.afterPropertiesSet();
        first = new StringRedisTemplate(firstFactory);
        second = new StringRedisTemplate(secondFactory);
    }
    @AfterAll static void disconnect() {
        if (firstFactory != null) firstFactory.destroy();
        if (secondFactory != null) secondFactory.destroy();
    }
    String client() { return UUID.randomUUID().toString(); }

    @Test void exactLimitAndIndependentAddressAndOperationBuckets() {
        RateLimitService limits = new RateLimitService(first, true, 2, 3, 60, 2, 2, 60, "test-only-secret");
        String ip = client();
        assertThat(limits.check("login", ip)).isZero();
        assertThat(limits.check("login", ip)).isZero();
        assertThat(limits.check("login", ip)).isBetween(1L, 60L);
        assertThat(limits.check("login", client())).isZero();
        assertThat(limits.check("refresh", ip)).isZero();
        assertThat(limits.check("refresh", ip)).isZero();
        assertThat(limits.check("refresh", ip)).isZero();
        assertThat(limits.check("refresh", ip)).isBetween(1L, 60L);
    }

    @Test void windowExpiresAndRejectedTrafficDoesNotExtendIt() {
        RateLimitService limits = new RateLimitService(first, true, 1, 1, 1, 2, 2, 60, "test-only-secret");
        String ip = client();
        assertThat(limits.check("login", ip)).isZero();
        assertThat(limits.check("login", ip)).isEqualTo(1);
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(limits.check("login", ip)).isZero());
    }

    @Test void concurrentCallsAcrossIndependentClientsShareOneLimit() throws Exception {
        RateLimitService left = new RateLimitService(first, true, 5, 5, 60, 2, 2, 60, "test-only-secret");
        RateLimitService right = new RateLimitService(second, true, 5, 5, 60, 2, 2, 60, "test-only-secret");
        String ip = client();
        ExecutorService executor = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Long>> results = new ArrayList<>();
        try {
            for (int i = 0; i < 40; i++) {
                RateLimitService service = i % 2 == 0 ? left : right;
                results.add(executor.submit(() -> {
                    if (!start.await(5, TimeUnit.SECONDS)) throw new AssertionError("timeout");
                    return service.check("login", ip);
                }));
            }
            start.countDown();
            int accepted = 0;
            for (Future<Long> result : results) if (result.get(10, TimeUnit.SECONDS) == 0) accepted++;
            assertThat(accepted).isEqualTo(5);
        } finally { start.countDown(); executor.shutdownNow(); }
    }

    @Test void disabledLimiterDoesNotContactRedis() {
        StringRedisTemplate unused = mock(StringRedisTemplate.class);
        assertThat(new RateLimitService(unused, false, 1, 1, 60, 2, 2, 60, "test-only-secret").check("login", client())).isZero();
        verifyNoInteractions(unused);
    }

    @Test void invalidConfigurationIsRejected() {
        assertThatThrownBy(() -> new RateLimitService(first, true, 0, 1, 60, 2, 2, 60, "test-only-secret")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RateLimitService(first, true, 1, 1, 0, 2, 2, 60, "test-only-secret")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test void accountBudgetIsSharedAcrossClientsAndNormalizesEmail() {
        RateLimitService left = new RateLimitService(first, true, 10, 30, 60, 2, 2, 60, "test-secret");
        RateLimitService right = new RateLimitService(second, true, 10, 30, 60, 2, 2, 60, "test-secret");
        String email = client() + "@example.com";
        left.enforceLoginAccount(email);
        left.recordFailedLogin(email);
        right.enforceLoginAccount(email.toUpperCase(java.util.Locale.ROOT));
        right.recordFailedLogin(email.toUpperCase(java.util.Locale.ROOT));
        assertThatThrownBy(() -> left.enforceLoginAccount(email))
                .isInstanceOf(com.simpath.app.common.RateLimitExceededException.class);
        right.enforceLoginAccount(client() + "@example.com");
    }
    @Test void registerHasItsOwnBudget() {
        RateLimitService limits = new RateLimitService(first, true, 10, 30, 60, 2, 2, 60, "test-secret");
        String ip = client();
        assertThat(limits.check("register", ip)).isZero();
        assertThat(limits.check("register", ip)).isZero();
        assertThat(limits.check("register", ip)).isPositive();
        assertThat(limits.check("login", ip)).isZero();
    }
    @Test void accountChecksDoNotConsumeAndFailureWindowExpires() {
        RateLimitService limits = new RateLimitService(first, true, 10, 30, 60, 2, 2, 1, "test-secret");
        String email = client() + "@example.com";
        for (int i = 0; i < 10; i++) limits.enforceLoginAccount(email);
        limits.recordFailedLogin(email);
        limits.enforceLoginAccount(email);
        limits.recordFailedLogin(email);
        assertThatThrownBy(() -> limits.enforceLoginAccount(email))
                .isInstanceOf(com.simpath.app.common.RateLimitExceededException.class);
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThatCode(() -> limits.enforceLoginAccount(email)).doesNotThrowAnyException());
    }

    @Test void concurrentFailuresSaturateWithoutExtendingAccountWindow() throws Exception {
        RateLimitService limits = new RateLimitService(first, true, 10, 30, 60, 2, 2, 60, "test-secret");
        String email = client() + "@example.com";
        ExecutorService executor = Executors.newFixedThreadPool(8);
        List<Future<?>> results = new ArrayList<>();
        try {
            for (int i = 0; i < 40; i++) results.add(executor.submit(() -> limits.recordFailedLogin(email)));
            for (Future<?> result : results) result.get(10, TimeUnit.SECONDS);
            assertThatThrownBy(() -> limits.enforceLoginAccount(email))
                    .isInstanceOf(com.simpath.app.common.RateLimitExceededException.class);
        } finally { executor.shutdownNow(); }
    }

}


