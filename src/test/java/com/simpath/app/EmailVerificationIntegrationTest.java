package com.simpath.app;

import com.simpath.app.auth.dto.*;
import com.simpath.app.auth.service.AuthService;
import com.simpath.app.user.entity.User;
import com.simpath.app.user.repo.UserRepository;
import com.simpath.app.verification.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "app.jwt.secret=test-only-key-with-at-least-thirty-two-characters",
        "app.refresh-token.pepper=test-only-pepper", "app.rate-limit.account-key=test-only-account-key",
        "app.verification.outbox-key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "app.verification.worker-enabled=false", "app.token-cleanup.cron=-",
        "app.rate-limit.register-limit=2", "app.rate-limit.refresh-limit=2",
        "spring.datasource.username=test", "spring.datasource.password=test"
})
@Import({AuthIntegrationTest.Containers.class, EmailVerificationIntegrationTest.MailConfiguration.class})
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class EmailVerificationIntegrationTest {
    @TestConfiguration(proxyBeanMethods = false)
    static class MailConfiguration {
        @Bean(initMethod = "start", destroyMethod = "stop")
        GenericContainer<?> mailpit() {
            return new GenericContainer<>(DockerImageName.parse("axllent/mailpit:v1.20")).withExposedPorts(1025);
        }
        @Bean JavaMailSender mailSender(@Qualifier("mailpit") GenericContainer<?> container) {
            JavaMailSenderImpl sender = new JavaMailSenderImpl();
            sender.setHost(container.getHost()); sender.setPort(container.getMappedPort(1025));
            sender.getJavaMailProperties().setProperty("mail.smtp.connectiontimeout", "2000");
            sender.getJavaMailProperties().setProperty("mail.smtp.timeout", "2000");
            sender.getJavaMailProperties().setProperty("mail.smtp.writetimeout", "2000");
            return sender;
        }
    }
    @Autowired AuthService auth;
    @Autowired VerificationService verification;
    @Autowired UserRepository users;
    @Autowired VerificationRepository tokens;
    @Autowired MailOutboxRepository outbox;
    @Autowired MailOutboxDelivery delivery;
    @MockitoSpyBean OutboxCipher cipher;
    @MockitoSpyBean VerificationMailer mail;
    @Autowired org.springframework.data.redis.core.StringRedisTemplate redis;
    @Autowired MockMvc mvc;
    private final String email = "verify@example.com";
    private final String password = "Correct-Horse-123!";

    @BeforeEach void clean() {
        users.deleteAll();
        try (org.springframework.data.redis.connection.RedisConnection connection = redis.getConnectionFactory().getConnection()) {
            connection.serverCommands().flushDb();
        }
    }
    void register() { auth.register(new RegisterRequest(email, password)); }
    String token() {
        MailOutbox item = outbox.findAll().get(0);
        return cipher.decrypt(item.getId(), item.getPayload()).split("\n", 2)[1];
    }
    void makeResendDue() {
        User user = users.findByEmail(email).orElseThrow();
        user.setVerificationSentAt(Instant.now().minusSeconds(120)); users.saveAndFlush(user);
    }

    @Test void registrationRequiresVerificationAndPersistsOnlyEncryptedDeliveryPayload() throws Exception {
        register();
        assertThat(users.findByEmail(email).orElseThrow().isEmailVerified()).isFalse();
        assertThat(tokens.count()).isEqualTo(1); assertThat(outbox.count()).isEqualTo(1);
        String plain = token();
        assertThat(tokens.findAll().get(0).getTokenHash()).isEqualTo(VerificationService.hash(plain));
        assertThat(outbox.findAll().get(0).getPayload()).doesNotContain(email, plain);
        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        mvc.perform(post("/auth/email-verification/confirm").header("Authorization", "Bearer stale")
                .contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + plain + "\"}"))
                .andExpect(status().isNoContent());
        assertThat(auth.login(new LoginRequest(email, password), "test", "ip").accessToken()).isNotBlank();
        assertThatThrownBy(() -> verification.confirm(plain)).isInstanceOf(InvalidVerificationException.class);
        delivery.scrub(); assertThat(outbox.findAll().get(0).getPayload()).isNull();
    }

    @Test void workerSendsViaRealSmtpAndScrubsCiphertextOnSuccess() {
        register(); String plain = token();
        assertThat(delivery.deliverOne()).isTrue();
        verify(mail).send(email, plain);
        MailOutbox sent = outbox.findAll().get(0);
        assertThat(sent.getAttempts()).isEqualTo(1);
        assertThat(sent.getFinishedAt()).isNotNull(); assertThat(sent.getPayload()).isNull();
        assertThat(delivery.deliverOne()).isFalse();
        verification.confirm(plain);
        assertThat(users.findByEmail(email).orElseThrow().isEmailVerified()).isTrue();
    }

    @Test void smtpFailureRetriesWithBackoffAndStopsAfterFiveAttempts() {
        register(); doThrow(new org.springframework.mail.MailSendException("test failure")).when(mail).send(anyString(), anyString());
        UUID id = outbox.findAll().get(0).getId();
        for (int i = 1; i <= 5; i++) {
            MailOutbox item = outbox.findById(id).orElseThrow();
            item.setNextAttemptAt(Instant.now().minusSeconds(1)); outbox.saveAndFlush(item);
            delivery.deliverOne();
            MailOutbox failed = outbox.findById(id).orElseThrow();
            assertThat(failed.getAttempts()).isEqualTo(i);
            if (i < 5) {
                assertThat(failed.getPayload()).isNotNull();
                assertThat(failed.getNextAttemptAt()).isAfter(Instant.now().plusSeconds(20));
                assertThat(delivery.deliverOne()).isFalse();
            }
        }
        assertThat(outbox.findById(id).orElseThrow().getPayload()).isNull();
        assertThat(delivery.deliverOne()).isFalse();
    }

    @Test void retryCanRecoverWithoutReissuingTheVerificationToken() {
        register(); String plain = token();
        doThrow(new org.springframework.mail.MailSendException("test failure")).doCallRealMethod().when(mail).send(anyString(), anyString());
        delivery.deliverOne();
        MailOutbox item = outbox.findAll().get(0); item.setNextAttemptAt(Instant.now().minusSeconds(1)); outbox.saveAndFlush(item);
        delivery.deliverOne();
        assertThat(outbox.findById(item.getId()).orElseThrow().getPayload()).isNull();
        verification.confirm(plain);
    }

    @Test void duplicateRegistrationDoesNotOverwritePasswordOrQueueMoreMail() {
        register();
        String hash = users.findByEmail(email).orElseThrow().getPasswordHash();
        auth.register(new RegisterRequest(email, "Another-Correct-Password!"));
        assertThat(users.findByEmail(email).orElseThrow().getPasswordHash()).isEqualTo(hash);
        assertThat(tokens.count()).isEqualTo(1); assertThat(outbox.count()).isEqualTo(1);
    }

    @Test void resendUsesCooldownAndDoesNotInvalidateEarlierLinks() {
        register(); String first = token();
        verification.request(email); assertThat(outbox.count()).isEqualTo(1);
        makeResendDue(); verification.request(email.toUpperCase(java.util.Locale.ROOT));
        assertThat(outbox.count()).isEqualTo(2);
        verification.confirm(first);
        delivery.scrub(); assertThat(outbox.findAll()).allMatch(item -> item.getPayload() == null);
    }

    @Test void unknownAndVerifiedAccountsReceiveTheSameGenericResponse() throws Exception {
        register(); verification.confirm(token());
        String known = mvc.perform(post("/auth/email-verification/request").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\"}")).andExpect(status().isAccepted()).andReturn().getResponse().getContentAsString();
        String unknown = mvc.perform(post("/auth/email-verification/request").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"unknown@example.com\"}")).andExpect(status().isAccepted()).andReturn().getResponse().getContentAsString();
        assertThat(known).isEqualTo(unknown); assertThat(outbox.count()).isEqualTo(1);
    }

    @Test void accountRequestBudgetAppliesToUnknownAccountsAndNormalizesCase() {
        for (int i = 0; i < 3; i++) verification.request("UNKNOWN@example.com");
        assertThatThrownBy(() -> verification.request("unknown@example.com"))
                .isInstanceOf(com.simpath.app.common.RateLimitExceededException.class);
    }

    @Test void encodedVerificationRoutesShareTheIpBudget() throws Exception {
        for (String path : List.of("/auth/email-verification/req%75est", "/auth/email-verification/request")) {
            mvc.perform(post(java.net.URI.create(path)).contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isBadRequest());
        }
        mvc.perform(post("/auth/email-verification/request").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isTooManyRequests());
    }

    @Test void expiredTokenIsRejectedAndDisabledAccountsReceiveNoMail() {
        register(); String plain = token();
        VerificationToken token = tokens.findAll().get(0); token.setExpiresAt(Instant.now().minusSeconds(1)); tokens.saveAndFlush(token);
        assertThatThrownBy(() -> verification.confirm(plain)).isInstanceOf(InvalidVerificationException.class);
        User user = users.findByEmail(email).orElseThrow(); user.setEnabled(false); users.saveAndFlush(user);
        delivery.scrub(); assertThat(outbox.findAll().get(0).getPayload()).isNull();
        assertThat(delivery.deliverOne()).isFalse(); verify(mail, never()).send(anyString(), anyString());
    }

    @Test void queueFailureRollsBackAccountAndTokenTogether() {
        doThrow(new IllegalStateException("test encryption failure")).when(cipher).encrypt(any(), anyString());
        assertThatThrownBy(this::register).isInstanceOf(IllegalStateException.class);
        assertThat(users.findByEmail(email)).isEmpty(); assertThat(tokens.count()).isZero(); assertThat(outbox.count()).isZero();
    }

    @Test void concurrentConsumersVerifyExactlyOnce() throws Exception {
        register(); String plain = token();
        ExecutorService pool = Executors.newFixedThreadPool(2); CountDownLatch start = new CountDownLatch(1);
        Callable<Boolean> consume = () -> {
            if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("timeout");
            try { verification.confirm(plain); return true; } catch (InvalidVerificationException expected) { return false; }
        };
        try {
            Future<Boolean> first = pool.submit(consume); Future<Boolean> second = pool.submit(consume); start.countDown();
            assertThat(first.get(20, TimeUnit.SECONDS) ^ second.get(20, TimeUnit.SECONDS)).isTrue();
            assertThat(tokens.findAll().get(0).getUsedAt()).isNotNull();
        } finally { start.countDown(); pool.shutdownNow(); }
    }

    @Test void concurrentWorkersClaimOnlyOneDelivery() throws Exception {
        register();
        ExecutorService pool = Executors.newFixedThreadPool(2); CountDownLatch start = new CountDownLatch(1);
        Callable<Boolean> send = () -> { if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("timeout"); return delivery.deliverOne(); };
        try {
            Future<Boolean> first = pool.submit(send); Future<Boolean> second = pool.submit(send); start.countDown();
            assertThat(first.get(20, TimeUnit.SECONDS) ^ second.get(20, TimeUnit.SECONDS)).isTrue();
            verify(mail, times(1)).send(anyString(), anyString());
        } finally { start.countDown(); pool.shutdownNow(); }
    }
    @Test void concurrentResendCannotUndoSuccessfulVerification() throws Exception {
        register(); String plain = token(); makeResendDue();
        ExecutorService pool = Executors.newFixedThreadPool(2); CountDownLatch start = new CountDownLatch(1);
        try {
            Future<?> confirm = pool.submit(() -> {
                try { if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("timeout"); }
                catch (InterruptedException ex) { throw new RuntimeException(ex); }
                verification.confirm(plain);
            });
            Future<?> resend = pool.submit(() -> {
                try { if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("timeout"); }
                catch (InterruptedException ex) { throw new RuntimeException(ex); }
                verification.request(email);
            });
            start.countDown(); confirm.get(20, TimeUnit.SECONDS); resend.get(20, TimeUnit.SECONDS);
            assertThat(users.findByEmail(email).orElseThrow().isEmailVerified()).isTrue();
            assertThat(auth.login(new LoginRequest(email, password), "test", "ip").accessToken()).isNotBlank();
        } finally { start.countDown(); pool.shutdownNow(); }
    }

}
