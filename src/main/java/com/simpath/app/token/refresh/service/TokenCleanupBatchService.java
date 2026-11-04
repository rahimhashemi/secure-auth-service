package com.simpath.app.token.refresh.service;

import com.simpath.app.token.refresh.repo.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;

@Service
public class TokenCleanupBatchService {
    private final RefreshTokenRepository tokens;

    public TokenCleanupBatchService(RefreshTokenRepository tokens) {
        this.tokens = tokens;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int deleteBatch(Instant cutoff, int batchSize) {
        return tokens.deleteExpiredBatch(cutoff, batchSize);
    }
}
