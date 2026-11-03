package com.simpath.app.common;
public class RateLimitUnavailableException extends RuntimeException {
    public RateLimitUnavailableException(Throwable cause) { super("Rate limiter unavailable", cause); }
}
