package com.irene.authentication.utils;

import com.irene.authentication.models.JwtResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
public class JwtUtil implements Serializable {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtil.class);

    private static final long serialVersionUID = -2550185165626007488L;
    public static final String AUTHORITIES_KEY = "authorities";

    @Value("${jwt.issuer}")
    private String issuer;
    @Value("${jwt.secret-key}")
    private String secret;
    @Value("${jwt.expiry-time-in-m}")
    private int expiryTime;
    @Value("${jwt.refresh-expiry-time-in-m}")
    private int refreshExpiryTime;

    private String getAuthorities(Authentication auth) {
        return auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
    }

    public SecretKey getKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public JwtResponse generateToken(Authentication auth) {
        LOGGER.debug("Generating token for '{}'.", auth.getPrincipal().toString());
        Date expire = Date.from(Instant.now().plusSeconds(TimeUnit.MINUTES.toSeconds(expiryTime)));

        String jwt = Jwts.builder()
                .setIssuer(issuer)
                .setSubject(auth.getPrincipal().toString())
                .claim(AUTHORITIES_KEY, getAuthorities(auth))
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(expire)
                .signWith(getKey())
                .compact();

        return new JwtResponse(jwt, String.valueOf(expire.getTime()/1000));
    }

    public JwtResponse generateRefreshToken(Claims claims) {
        String user = claims.get("sub").toString();
        LOGGER.debug("Generating refresh token for '{}'.", user);
        ArrayList auths = (ArrayList) claims.get(AUTHORITIES_KEY);
        Date expire = Date.from(Instant.now().plusSeconds(TimeUnit.MINUTES.toSeconds(refreshExpiryTime)));
        String jwt = Jwts.builder()
                .setIssuer(issuer)
                .setSubject(user)
                .claim(AUTHORITIES_KEY, auths.toArray())
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(expire)
                .signWith(getKey())
                .compact();
        return new JwtResponse(jwt, String.valueOf(expire.getTime()/1000));
    }

}
