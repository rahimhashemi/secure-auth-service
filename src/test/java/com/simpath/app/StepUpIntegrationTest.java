package com.simpath.app;

import com.simpath.app.auth.dto.AuthResponse;
import com.simpath.app.auth.dto.LoginRequest;
import com.simpath.app.auth.dto.RefreshRequest;
import com.simpath.app.auth.dto.RegisterRequest;
import com.simpath.app.auth.service.AuthService;
import com.simpath.app.mfa.MfaDtos;
import com.simpath.app.mfa.MfaService;
import com.simpath.app.mfa.TotpService;
import com.simpath.app.mfa.UserMfa;
import com.simpath.app.mfa.UserMfaRepository;
import com.simpath.app.session.AuthSession;
import com.simpath.app.session.InvalidStepUpException;
import com.simpath.app.session.SessionRepository;
import com.simpath.app.session.SessionService;
import com.simpath.app.session.StepUpRequiredException;
import com.simpath.app.session.StepUpService;
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
import javax.crypto.SecretKey;
import java.time.Instant;
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
class StepUpIntegrationTest {
    @Autowired AuthService auth;
    @Autowired UserRepository users;
    @Autowired SessionService sessionService;
    @Autowired SessionRepository sessions;
    @Autowired StepUpService stepUp;
    @Autowired MfaService mfa;
    @Autowired TotpService totp;
    @Autowired UserMfaRepository factors;
    @Autowired SecretKey jwtKey;
    @Autowired MockMvc mvc;

    private final String email = "step-up-" + UUID.randomUUID() + "@example.com";
    private final String password = UUID.randomUUID() + "-Ab1!";

    private UUID registerVerified() {
        auth.register(new RegisterRequest(email, password));
        User user = users.findByEmail(email).orElseThrow();
        user.setEmailVerified(true);
        users.saveAndFlush(user);
        return user.getId();
    }

    private AuthResponse login() {
        return auth.login(new LoginRequest(email, password), "test", "127.0.0.1");
    }

    private UUID sessionId(AuthResponse response) {
        return UUID.fromString(io.jsonwebtoken.Jwts.parserBuilder()
                .setSigningKey(jwtKey).build().parseClaimsJws(response.accessToken())
                .getBody().get("sid", String.class));
    }

    private void expireStepUp(UUID sid) {
        AuthSession session = sessions.findById(sid).orElseThrow();
        session.setLastStepUpAt(Instant.now().minusSeconds(600));
        sessions.saveAndFlush(session);
    }

    @Test void sessionRevocationNeedsRecentProofAndRefreshCannotExtendIt() throws Exception {
        UUID userId = registerVerified();
        AuthResponse current = login();
        AuthResponse other = login();
        UUID sid = sessionId(current);
        expireStepUp(sid);

        assertThat(sessionService.stepUpStatus(userId, sid).isElevated()).isFalse();
        assertThatThrownBy(() -> sessionService.revokeOtherSessions(userId, sid))
                .isInstanceOf(StepUpRequiredException.class);

        mvc.perform(delete("/sessions/others").header("Authorization", "Bearer " + current.accessToken()))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("STEP_UP_REQUIRED"));
        mvc.perform(get("/sessions/step-up").header("Authorization", "Bearer " + current.accessToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.elevated").value(false));

        mvc.perform(post("/sessions/step-up").header("Authorization", "Bearer " + current.accessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.validUntil").exists());
        assertThat(sessionService.stepUpStatus(userId, sid).isElevated()).isTrue();

        mvc.perform(delete("/sessions/others").header("Authorization", "Bearer " + current.accessToken()))
                .andExpect(status().isNoContent());
        assertThatThrownBy(() -> auth.refresh(new RefreshRequest(other.refreshToken()), "test", "ip"))
                .isInstanceOf(com.simpath.app.common.InvalidRefreshTokenException.class);

        expireStepUp(sid);
        AuthResponse rotated = auth.refresh(new RefreshRequest(current.refreshToken()), "test", "ip");
        assertThat(sessionId(rotated)).isEqualTo(sid);
        assertThat(sessionService.stepUpStatus(userId, sid).isElevated()).isFalse();
    }

    @Test void enrolledAccountsRequireFreshTotpAndRejectReplay() {
        UUID userId = registerVerified();
        login();
        MfaDtos.SetupResponse setup = mfa.setup(userId, password, null, null);
        mfa.confirm(userId, totp.codeAt(setup.getSecret(), Instant.now()), null, null);
        AuthResponse pending = login();
        // Confirm response codes are one-time; verify login with a fresh TOTP window
        // simulated by adjusting the previous counter rather than sleeping.
        UserMfa factor = factors.findById(userId).orElseThrow();
        factor.setLastUsedCounter(-1);
        factors.saveAndFlush(factor);
        AuthResponse active = mfa.verifyChallenge(pending.mfaChallengeToken(),
                totp.codeAt(setup.getSecret(), Instant.now()), null, null);
        UUID sid = sessionId(active);
        expireStepUp(sid);

        assertThatThrownBy(() -> stepUp.elevate(userId, sid, password, null, null, null))
                .isInstanceOf(InvalidStepUpException.class);
        assertThatThrownBy(() -> stepUp.elevate(userId, sid, "incorrect", null, null, null))
                .isInstanceOf(InvalidStepUpException.class);

        factor = factors.findById(userId).orElseThrow();
        factor.setLastUsedCounter(-1);
        factors.saveAndFlush(factor);
        String freshCode = totp.codeAt(setup.getSecret(), Instant.now());
        assertThat(stepUp.elevate(userId, sid, password, freshCode, null, null).getValidUntil())
                .isAfter(Instant.now());
        expireStepUp(sid);
        assertThatThrownBy(() -> stepUp.elevate(userId, sid, password, freshCode, null, null))
                .isInstanceOf(InvalidStepUpException.class);
    }
}
