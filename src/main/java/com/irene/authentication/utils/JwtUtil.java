package com.irene.authentication.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtUtil implements Serializable {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtil.class);

    private static final long serialVersionUID = -2550185165626007488L;
    public static final String AUTHORITIES_KEY = "roles";

    @Value("${jwt.issuer}")
    private String issuer;
    @Value("${jwt.secret-key}")
    private String secret;
    @Value("${jwt.expiry-time-in-m}")
    private int expiryTime;
    @Value("${jwt.refresh-expiry-time-in-m}")
    private int refreshExpiryTime;

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(getKey()).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            throw new AuthenticationServiceException("Expired or invalid JWT token.", e);
        }
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token).getBody();
    }

    private boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private String getAuthorities(Authentication auth) {
        return auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
    }

    public SecretKey getKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(Authentication auth) {
        LOGGER.info("Generating token for '{}'.", auth.getPrincipal().toString());
        return Jwts.builder()
                .setIssuer(issuer)
                .setSubject(auth.getPrincipal().toString())
                .claim(AUTHORITIES_KEY, getAuthorities(auth))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiryTime * 1_000 * 60))
                .signWith(getKey()).compact();
    }

    public String generateRefreshToken(Claims claims) {
        String user = claims.get("sub").toString();
        LOGGER.info("Generating refresh token for '{}'.", user);
        return Jwts.builder()
                    .setIssuer(issuer)
                    .setSubject(user)
                    .claim(AUTHORITIES_KEY, claims.get(AUTHORITIES_KEY))
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + refreshExpiryTime * 1_000 * 60))
                    .signWith(getKey()).compact();
    }

}
