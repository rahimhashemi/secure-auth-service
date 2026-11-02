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
    private final String issuer;

    public JwtAuthFilter(
            SecretKey key,
            @Value("${app.jwt.issuer}") String issuer
    ) {
        this.key = key;
        this.issuer = issuer;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return "POST".equals(request.getMethod()) && ("/auth/login".equals(path)
                || "/auth/register".equals(path) || "/auth/refresh".equals(path));
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
                String email = claims.get("email", String.class);

                AuthPrincipal principal = new AuthPrincipal(userId, email);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))
                );

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (io.jsonwebtoken.JwtException | IllegalArgumentException ex) {
            // If token invalid, clear context and continue (will be blocked by security if needed)
            SecurityContextHolder.clearContext();
            try {
                response.setStatus(401);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"invalid_token\"}");
            } catch (java.io.IOException ignored) {
            }
            return;
        }
        filterChain.doFilter(request, response);
    }
}


