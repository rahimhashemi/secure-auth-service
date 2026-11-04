package com.simpath.app.token.refresh.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

@Service
public class TokenCleanupService {
    private final TokenCleanupBatchService batches;
    private final boolean enabled;
    private final int retentionDays;
    private final int batchSize;
    private final int maxBatches;
    private final long maxRuntimeNanos;

    public TokenCleanupService(TokenCleanupBatchService batches,
            @Value("${app.token-cleanup.enabled:true}") boolean enabled,
            @Value("${app.token-cleanup.retention-days:30}") int retentionDays,
            @Value("${app.token-cleanup.batch-size:1000}") int batchSize,
            @Value("${app.token-cleanup.max-batches:10}") int maxBatches,
            @Value("${app.token-cleanup.max-runtime-seconds:5}") int maxRuntimeSeconds) {
        if (retentionDays < 1 || batchSize < 1 || batchSize > 10000
                || maxBatches < 1 || maxBatches > 1000 || maxRuntimeSeconds < 1 || maxRuntimeSeconds > 300) {
            throw new IllegalArgumentException("Invalid token cleanup settings");
        }
        this.batches = batches;
        this.enabled = enabled;
        this.retentionDays = retentionDays;
        this.batchSize = batchSize;
        this.maxBatches = maxBatches;
        this.maxRuntimeNanos = TimeUnit.SECONDS.toNanos(maxRuntimeSeconds);
    }

    @Scheduled(cron = "${app.token-cleanup.cron:0 0 * * * *}")
    public void cleanup() {
        if (!enabled) return;
        Instant cutoff = Instant.now().minus(retentionDays, ChronoUnit.DAYS);
        long started = System.nanoTime();
        for (int batch = 0; batch < maxBatches; batch++) {
            if (System.nanoTime() - started >= maxRuntimeNanos) return;
            if (batches.deleteBatch(cutoff, batchSize) < batchSize) return;
        }
    }
}
