package com.simpath.app.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.dao.DataAccessException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Created inside the security chain, not a servlet bean: executes once before authentication.
public class RateLimitFilter extends OncePerRequestFilter {
    private final RateLimitService limits;
    private final ClientAddressResolver addresses;
    private final com.simpath.app.common.ApiErrorWriter errors;

    public RateLimitFilter(RateLimitService limits, ClientAddressResolver addresses, com.simpath.app.common.ApiErrorWriter errors) {
        this.limits = limits;
        this.addresses = addresses;
        this.errors = errors;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String operation = AuthEndpointMatcher.operation(request);
        if (operation == null) {
            chain.doFilter(request, response);
            return;
        }
        long retryAfter;
        try {
            // Do not trust client-supplied X-Forwarded-For or Forwarded headers.
            retryAfter = limits.check(operation, addresses.resolve(request));
        } catch (DataAccessException ex) {
            reject(request, response, 503, "RATE_LIMIT_UNAVAILABLE", "Authentication temporarily unavailable.", 1);
            return;
        }
        if (retryAfter > 0) {
            reject(request, response, 429, "RATE_LIMIT_EXCEEDED", "Too many requests. Try again later.", retryAfter);
            return;
        }
        chain.doFilter(request, response);
    }

    private void reject(HttpServletRequest request, HttpServletResponse response, int status,
                        String code, String message, long retryAfter) throws IOException {
        response.setHeader("Retry-After", Long.toString(retryAfter));
        errors.write(request, response, status, code, message);
    }
}
