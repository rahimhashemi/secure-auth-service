package com.simpath.app.token.refresh.service;

import com.simpath.app.token.refresh.repo.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;

@Service
public class TokenCleanupBatchService {
    private final RefreshTokenRepository tokens;
    private final com.simpath.app.passwordreset.PasswordResetRepository resets;
    private final com.simpath.app.verification.VerificationRepository verification;
    private final com.simpath.app.session.SessionRepository sessions;
    private final com.simpath.app.mfa.MfaLoginChallengeRepository challenges;

    public TokenCleanupBatchService(RefreshTokenRepository tokens, com.simpath.app.session.SessionRepository sessions, com.simpath.app.verification.VerificationRepository verification, com.simpath.app.passwordreset.PasswordResetRepository resets, com.simpath.app.mfa.MfaLoginChallengeRepository challenges) {
        this.tokens = tokens;
        this.resets = resets;
        this.verification = verification;
        this.sessions = sessions;
        this.challenges = challenges;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int deleteBatch(Instant cutoff, int batchSize) {
        int tokenCount = tokens.deleteExpiredBatch(cutoff, batchSize);
        int sessionCount = sessions.deleteExpiredBatch(cutoff, batchSize);
        int verificationCount = verification.deleteExpired(cutoff, batchSize);
        int resetCount = resets.deleteExpired(cutoff, batchSize);
        int challengeCount = challenges.deleteExpired(cutoff, batchSize);
        return Math.max(Math.max(tokenCount, sessionCount), Math.max(Math.max(verificationCount, resetCount), challengeCount));
    }
}
