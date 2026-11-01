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

    public RateLimitFilter(RateLimitService limits) {
        this.limits = limits;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        String operation = switch (path) {
            case "/auth/login", "/auth/login/" -> "login";
            case "/auth/refresh", "/auth/refresh/" -> "refresh";
            default -> null;
        };
        if (!"POST".equals(request.getMethod()) || operation == null) {
            chain.doFilter(request, response);
            return;
        }
        long retryAfter;
        try {
            // Do not trust client-supplied X-Forwarded-For or Forwarded headers.
            retryAfter = limits.check(operation, request.getRemoteAddr());
        } catch (DataAccessException ex) {
            reject(response, 503, "RATE_LIMIT_UNAVAILABLE", "Authentication temporarily unavailable.", 1);
            return;
        }
        if (retryAfter > 0) {
            reject(response, 429, "RATE_LIMIT_EXCEEDED", "Too many requests. Try again later.", retryAfter);
            return;
        }
        chain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, int status, String code, String message,
                        long retryAfter) throws IOException {
        response.setStatus(status);
        response.setHeader("Retry-After", Long.toString(retryAfter));
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}");
    }
}
