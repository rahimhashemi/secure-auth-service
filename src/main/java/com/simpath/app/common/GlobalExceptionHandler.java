package com.simpath.app.common;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiError> credentials(InvalidCredentialsException ex, HttpServletRequest req) {
        return ResponseEntity.status(401).body(ApiError.of("INVALID_CREDENTIALS", "Invalid credentials.", req.getRequestURI()));
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ApiError> limited(RateLimitExceededException ex, HttpServletRequest req) {
        return ResponseEntity.status(429).header("Retry-After", Long.toString(ex.getRetryAfter()))
                .header("Cache-Control", "no-store")
                .body(ApiError.of("RATE_LIMIT_EXCEEDED", "Too many requests. Try again later.", req.getRequestURI()));
    }

    @ExceptionHandler(RateLimitUnavailableException.class)
    public ResponseEntity<ApiError> unavailable(RateLimitUnavailableException ex, HttpServletRequest req) {
        return ResponseEntity.status(503).header("Retry-After", "1").header("Cache-Control", "no-store")
                .body(ApiError.of("RATE_LIMIT_UNAVAILABLE", "Authentication temporarily unavailable.", req.getRequestURI()));
    }

    @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> malformed(Exception ex, HttpServletRequest req) {
        return ResponseEntity.badRequest().body(ApiError.of("BAD_REQUEST", "Invalid request body.", req.getRequestURI()));
    }


    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ApiError> invalidRefresh(InvalidRefreshTokenException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiError.of("INVALID_REFRESH_TOKEN", "Invalid refresh token.", req.getRequestURI()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> validation(MethodArgumentNotValidException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiError.of("VALIDATION_ERROR", "Request validation failed.", req.getRequestURI()));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiError> constraint(ConstraintViolationException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiError.of("VALIDATION_ERROR", "Constraint violation.", req.getRequestURI()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> fallback(Exception ex, HttpServletRequest req) {
        String errorId = java.util.UUID.randomUUID().toString();
        // Never log request bodies, credentials, Authorization headers or token values.
        LOG.error("Unhandled request error id={} method={} path={}", errorId, req.getMethod(), req.getRequestURI(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).header("X-Error-Id", errorId)
                .body(ApiError.of("INTERNAL_ERROR", "Unexpected error.", req.getRequestURI()));
    }
}

