package com.simpath.app.token.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.util.List;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final SecretKey key;
    private final com.simpath.app.session.SessionService sessions;
    private final String issuer;
    private final com.simpath.app.common.ApiErrorWriter errors;

    public JwtAuthFilter(
            SecretKey key,
            @Value("${app.jwt.issuer}") String issuer,
            com.simpath.app.common.ApiErrorWriter errors,
            com.simpath.app.session.SessionService sessions
    ) {
        this.key = key;
        this.issuer = issuer;
        this.errors = errors;
        this.sessions = sessions;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return com.simpath.app.security.AuthEndpointMatcher.operation(request) != null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws jakarta.servlet.ServletException, java.io.IOException {
        try {
            String auth = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring("Bearer ".length()).trim();

                Claims claims = Jwts.parserBuilder()
                        .requireIssuer(issuer)
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                String userId = claims.getSubject();
                String sid = claims.get("sid", String.class);
                if (userId == null || sid == null || claims.getExpiration() == null) {
                    throw new IllegalArgumentException("Required token claim missing");
                }
                AuthPrincipal principal = sessions.authorize(java.util.UUID.fromString(userId), java.util.UUID.fromString(sid));
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
                );

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (io.jsonwebtoken.JwtException | IllegalArgumentException | com.simpath.app.session.InvalidSessionException ex) {
            // Reject invalid claims or inactive sessions before invoking the endpoint.
            SecurityContextHolder.clearContext();
            errors.write(request, response, 401, "INVALID_TOKEN", "Invalid access token.");
            return;
        } catch (org.springframework.dao.DataAccessException ex) {
            SecurityContextHolder.clearContext();
            response.setHeader("Retry-After", "1");
            errors.write(request, response, 503, "SESSION_STORE_UNAVAILABLE", "Authentication temporarily unavailable.");
            return;
        }
        filterChain.doFilter(request, response);
    }
}



