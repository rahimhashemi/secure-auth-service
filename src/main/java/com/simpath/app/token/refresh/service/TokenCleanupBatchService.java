package com.simpath.app.token.refresh.service;

import com.simpath.app.token.refresh.repo.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;

@Service
public class TokenCleanupBatchService {
    private final RefreshTokenRepository tokens;
    private final com.simpath.app.session.SessionRepository sessions;

    public TokenCleanupBatchService(RefreshTokenRepository tokens, com.simpath.app.session.SessionRepository sessions) {
        this.tokens = tokens;
        this.sessions = sessions;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int deleteBatch(Instant cutoff, int batchSize) {
        int tokenCount = tokens.deleteExpiredBatch(cutoff, batchSize);
        int sessionCount = sessions.deleteExpiredBatch(cutoff, batchSize);
        return Math.max(tokenCount, sessionCount);
    }
}
