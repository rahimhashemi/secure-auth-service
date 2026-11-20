package com.simpath.app;

import com.simpath.app.auth.dto.AuthResponse;
import com.simpath.app.auth.dto.LoginRequest;
import com.simpath.app.auth.dto.RegisterRequest;
import com.simpath.app.auth.service.AuthService;
import com.simpath.app.mfa.InvalidMfaException;
import com.simpath.app.mfa.MfaDtos;
import com.simpath.app.mfa.MfaService;
import com.simpath.app.mfa.TotpService;
import com.simpath.app.user.entity.User;
import com.simpath.app.user.repo.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "app.jwt.secret=test-only-key-with-at-least-thirty-two-characters",
        "app.refresh-token.pepper=test-only-pepper",
        "app.verification.outbox-key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "app.verification.worker-enabled=false",
        "app.rate-limit.account-key=test-only-account-key",
        "app.rate-limit.enabled=false",
        "spring.datasource.username=test", "spring.datasource.password=test",
        "app.token-cleanup.cron=-",
        "springdoc.api-docs.enabled=false", "springdoc.swagger-ui.enabled=false"
})
@Import(AuthIntegrationTest.Containers.class)
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class MfaIntegrationTest {
    @Autowired AuthService auth;
    @Autowired MfaService mfa;
    @Autowired TotpService totp;
    @Autowired UserRepository users;
    @Autowired MockMvc mvc;

    private final String email = "mfa-flow-" + UUID.randomUUID() + "@example.com";
    private final String password = UUID.randomUUID() + "-Ab1!";

    private UUID registerVerified() {
        auth.register(new RegisterRequest(email, password));
        User user = users.findByEmail(email).orElseThrow();
        user.setEmailVerified(true);
        users.saveAndFlush(user);
        return user.getId();
    }

    private AuthResponse login() {
        return auth.login(new LoginRequest(email, password), "integration", "127.0.0.1");
    }

    private MfaDtos.RecoveryResponse enable(UUID userId) {
        MfaDtos.SetupResponse setup = mfa.setup(userId, password, null, null);
        assertThat(setup.getProvisioningUri()).contains(setup.getSecret());
        assertThat(mfa.status(userId).isPending()).isTrue();
        return mfa.confirm(userId, totp.codeAt(setup.getSecret(), Instant.now()),
                "127.0.0.1", "integration");
    }

    @Test void mfaLoginDoesNotIssueTokensUntilOneTimeFactorIsVerified() throws Exception {
        UUID userId = registerVerified();
        AuthResponse oldSession = login();
        assertThat(oldSession.accessToken()).isNotBlank();

        assertThatThrownBy(() -> mfa.setup(userId, "wrong-password", "ip", "agent"))
                .isInstanceOf(InvalidMfaException.class);

        MfaDtos.RecoveryResponse recovery = enable(userId);
        assertThat(recovery.getRecoveryCodes()).hasSize(10).doesNotHaveDuplicates();
        mvc.perform(get("/me").header("Authorization", "Bearer " + oldSession.accessToken()))
                .andExpect(status().isUnauthorized());

        AuthResponse pending = login();
        assertThat(pending.mfaRequired()).isTrue();
        assertThat(pending.accessToken()).isNull();
        assertThat(pending.refreshToken()).isNull();
        assertThat(pending.mfaChallengeToken()).hasSize(43);

        assertThatThrownBy(() -> mfa.verifyChallenge(pending.mfaChallengeToken(), "000000", "agent", "ip"))
                .isInstanceOf(InvalidMfaException.class);

        String recoveryCode = recovery.getRecoveryCodes().get(0);
        AuthResponse verified = mfa.verifyChallenge(pending.mfaChallengeToken(), recoveryCode, "agent", "ip");
        assertThat(verified.accessToken()).isNotBlank();
        assertThat(verified.refreshToken()).isNotBlank();
        assertThat(verified.mfaRequired()).isFalse();

        assertThatThrownBy(() -> mfa.verifyChallenge(pending.mfaChallengeToken(), recoveryCode, "agent", "ip"))
                .isInstanceOf(InvalidMfaException.class);
        AuthResponse nextPending = login();
        assertThatThrownBy(() -> mfa.verifyChallenge(nextPending.mfaChallengeToken(), recoveryCode, "agent", "ip"))
                .isInstanceOf(InvalidMfaException.class);

        mvc.perform(get("/me").header("Authorization", "Bearer " + verified.accessToken()))
                .andExpect(status().isOk());
        mvc.perform(get("/auth/mfa/status")).andExpect(status().isUnauthorized());
        mvc.perform(get("/auth/mfa/status").header("Authorization", "Bearer " + verified.accessToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.enabled").value(true));
    }

    @Test void challengeHasFiveFailuresThenRemainsUnusable() {
        UUID userId = registerVerified();
        enable(userId);
        AuthResponse pending = login();
        for (int i = 0; i < 5; i++) {
            assertThatThrownBy(() -> mfa.verifyChallenge(pending.mfaChallengeToken(), "bad-code", "agent", "ip"))
                    .isInstanceOf(InvalidMfaException.class);
        }
        assertThatThrownBy(() -> mfa.verifyChallenge(pending.mfaChallengeToken(), "bad-code", "agent", "ip"))
                .isInstanceOf(InvalidMfaException.class);
    }

    @Test void disableRequiresPasswordAndFactorAndRevokesSessions() {
        UUID userId = registerVerified();
        MfaDtos.RecoveryResponse recovery = enable(userId);
        AuthResponse pending = login();
        AuthResponse active = mfa.verifyChallenge(pending.mfaChallengeToken(), recovery.getRecoveryCodes().get(0),
                "agent", "ip");
        assertThatThrownBy(() -> mfa.disable(userId, "incorrect", recovery.getRecoveryCodes().get(1), "ip", "agent"))
                .isInstanceOf(InvalidMfaException.class);
        mfa.disable(userId, password, recovery.getRecoveryCodes().get(1), "ip", "agent");
        assertThat(mfa.status(userId).isEnabled()).isFalse();
        assertThat(login().mfaRequired()).isFalse();
        assertThatThrownBy(() -> auth.refresh(new com.simpath.app.auth.dto.RefreshRequest(active.refreshToken()),
                "agent", "ip")).isInstanceOf(com.simpath.app.common.InvalidRefreshTokenException.class);
    }

    @Test void protectedRoutesRequireAccessTokenAndFailedOtpReturnsGenericError() throws Exception {
        mvc.perform(post("/auth/mfa/totp/setup").contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"any\"}")).andExpect(status().isUnauthorized());
        mvc.perform(post("/auth/mfa/challenge/verify").contentType(MediaType.APPLICATION_JSON)
                .content("{\"challengeToken\":\"invalid\",\"code\":\"123456\"}"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_MFA"));
    }
}
