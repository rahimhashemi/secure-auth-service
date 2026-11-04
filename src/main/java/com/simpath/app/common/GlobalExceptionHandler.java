package com.simpath.app.common;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler extends org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(com.simpath.app.session.InvalidSessionException.class)
    public ResponseEntity<ApiError> invalidSession(com.simpath.app.session.InvalidSessionException ex, HttpServletRequest req) {
        return ResponseEntity.status(401).body(ApiError.of("INVALID_TOKEN", "Invalid access token.", req.getRequestURI()));
    }

    @ExceptionHandler(com.simpath.app.verification.InvalidVerificationException.class)
    public ResponseEntity<ApiError> invalidVerification(com.simpath.app.verification.InvalidVerificationException ex, HttpServletRequest req) {
        return ResponseEntity.badRequest().body(ApiError.of("INVALID_VERIFICATION_TOKEN", "Invalid or expired verification token.", req.getRequestURI()));
    }

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

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ApiError> invalidRefresh(InvalidRefreshTokenException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiError.of("INVALID_REFRESH_TOKEN", "Invalid refresh token.", req.getRequestURI()));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiError> constraint(ConstraintViolationException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiError.of("VALIDATION_ERROR", "Constraint violation.", req.getRequestURI()));
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body,
            org.springframework.http.HttpHeaders headers, org.springframework.http.HttpStatusCode status,
            org.springframework.web.context.request.WebRequest request) {
        String path = request instanceof org.springframework.web.context.request.ServletWebRequest servlet
                ? servlet.getRequest().getRequestURI() : "";
        String code = switch (status.value()) {
            case 400 -> ex instanceof MethodArgumentNotValidException ? "VALIDATION_ERROR" : "BAD_REQUEST";
            case 404 -> "NOT_FOUND";
            case 405 -> "METHOD_NOT_ALLOWED";
            case 406 -> "NOT_ACCEPTABLE";
            case 415 -> "UNSUPPORTED_MEDIA_TYPE";
            default -> status.is4xxClientError() ? "REQUEST_ERROR" : "INTERNAL_ERROR";
        };
        String message = status.is5xxServerError() ? "Unexpected error." : "Request cannot be processed.";
        // Delegate committed-response handling and preserve Allow/Accept and other framework headers.
        return super.handleExceptionInternal(ex, ApiError.of(code, message, path), headers, status, request);
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



