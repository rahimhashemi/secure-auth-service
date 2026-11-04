package com.simpath.app.token.token;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Service
public class JwtService {

    private final SecretKey key;
    private final String issuer;
    @Getter
    private final long accessTtlSeconds;

    public JwtService(
            SecretKey key,
            @Value("${app.jwt.issuer}") String issuer,
            @Value("${app.jwt.access-ttl-minutes}") long accessTtlMinutes
    ) {
        this.key = key;
        this.issuer = issuer;
        this.accessTtlSeconds = accessTtlMinutes * 60;
    }

    public String issueAccessToken(UUID userId, String email, UUID sessionId) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(accessTtlSeconds);

        return Jwts.builder()
                .setIssuer(issuer)
                .setSubject(userId.toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .addClaims(Map.of("email", email, "sid", sessionId.toString()))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

}

