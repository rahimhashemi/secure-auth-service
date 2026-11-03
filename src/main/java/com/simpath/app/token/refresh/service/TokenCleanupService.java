package com.simpath.app.token.refresh.service;

import com.simpath.app.token.refresh.repo.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class TokenCleanupService {
    private final RefreshTokenRepository tokens;
    private final boolean enabled;
    private final int retentionDays;
    private final int batchSize;
    public TokenCleanupService(RefreshTokenRepository tokens,
            @Value("${app.token-cleanup.enabled:true}") boolean enabled,
            @Value("${app.token-cleanup.retention-days:30}") int retentionDays,
            @Value("${app.token-cleanup.batch-size:1000}") int batchSize) {
        if (retentionDays < 1 || batchSize < 1 || batchSize > 10000) throw new IllegalArgumentException("Invalid token cleanup settings");
        this.tokens = tokens; this.enabled = enabled; this.retentionDays = retentionDays; this.batchSize = batchSize;
    }
    @Scheduled(cron = "${app.token-cleanup.cron:0 0 * * * *}")
    @Transactional
    public void cleanup() {
        if (enabled) tokens.deleteExpiredBatch(Instant.now().minus(retentionDays, ChronoUnit.DAYS), batchSize);
    }
}
