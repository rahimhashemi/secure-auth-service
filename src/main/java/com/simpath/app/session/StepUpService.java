package com.simpath.app.session;

import com.simpath.app.audit.AuditService;
import com.simpath.app.mfa.MfaService;
import com.simpath.app.security.PasswordService;
import com.simpath.app.security.RateLimitService;
import com.simpath.app.user.entity.User;
import com.simpath.app.user.repo.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.UUID;

@Service
public class StepUpService {
    private final UserRepository users;
    private final PasswordService passwords;
    private final RateLimitService limits;
    private final MfaService mfa;
    private final SessionService sessions;
    private final AuditService audit;

    public StepUpService(UserRepository users, PasswordService passwords, RateLimitService limits,
            MfaService mfa, SessionService sessions, AuditService audit) {
        this.users = users;
        this.passwords = passwords;
        this.limits = limits;
        this.mfa = mfa;
        this.sessions = sessions;
        this.audit = audit;
    }

    @Transactional
    public StepUpDtos.Response elevate(UUID userId, UUID sessionId, String password,
            String code, String ip, String userAgent) {
        // Serializes reauthentication, MFA replay checks and session mutations across instances.
        User user = users.lockById(userId)
                .filter(account -> account.isEnabled() && account.isEmailVerified())
                .orElseThrow(InvalidSessionException::new);

        limits.enforceLoginAccount(user.getEmail());
        if (!passwords.matches(password, user.getPasswordHash())) {
            reject(user, ip, userAgent);
        }

        boolean mfaEnabled = mfa.isEnabled(userId);
        if (mfaEnabled && !mfa.verifyTotpForStepUp(userId, code)) {
            reject(user, ip, userAgent);
        }

        Instant validUntil = sessions.grantStepUp(userId, sessionId);
        audit.log("SESSION_STEP_UP", userId, mfaEnabled ? "password_and_totp" : "password",
                ip, userAgent);
        return new StepUpDtos.Response(validUntil);
    }

    private void reject(User user, String ip, String userAgent) {
        limits.recordFailedLogin(user.getEmail());
        audit.log("SESSION_STEP_UP_FAILED", user.getId(), null, ip, userAgent);
        throw new InvalidStepUpException();
    }
}
