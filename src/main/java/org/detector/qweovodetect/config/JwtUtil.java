package org.detector.qweovodetect.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.detector.qweovodetect.stats.AuthConfigService;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {

    private static final long EXPIRATION = 86400000;
    private static final String TOKEN_VERSION_CLAIM = "tokenVersion";

    private final AuthConfigService authConfigService;

    public JwtUtil(AuthConfigService authConfigService) {
        this.authConfigService = authConfigService;
    }

    private SecretKey getKey() {
        return Keys.hmacShaKeyFor(Base64.getDecoder().decode(authConfigService.currentJwtSecret()));
    }

    public String generateToken(String username) {
        return Jwts.builder()
                .subject(username)
                .claim(TOKEN_VERSION_CLAIM, authConfigService.currentTokenVersion())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION))
                .signWith(getKey())
                .compact();
    }

    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = parseToken(token);
            Integer tokenVersion = claims.get(TOKEN_VERSION_CLAIM, Integer.class);
            return tokenVersion != null
                    && authConfigService.isTokenCurrent(claims.getSubject(), tokenVersion);
        } catch (Exception e) {
            return false;
        }
    }

    public String getUsername(String token) {
        return parseToken(token).getSubject();
    }
}
