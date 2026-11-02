package com.simpath.app.common;
public class RateLimitExceededException extends RuntimeException {
    private final long retryAfter;
    public RateLimitExceededException(long retryAfter) { this.retryAfter = retryAfter; }
    public long getRetryAfter() { return retryAfter; }
}
