package com.irene.authentication.controller;

import com.irene.authentication.providers.AuthenticationToken;
import com.irene.authentication.models.JwtResponse;
import com.irene.authentication.models.AuthenticationRequest;
import com.irene.authentication.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;


import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

@RestController
public class AuthController {

    public static final String token= "/token";
    public static final String refreshToken= "/refreshToken";

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping(value = token)
    public ResponseEntity generateToken(@Valid AuthenticationRequest authRequest) {
        Authentication auth = null;
        try{
            LOGGER.info("Authenticating user.");
            auth = authenticationManager.authenticate(new AuthenticationToken(authRequest.getUsername(), authRequest.getPassword(),
                    authRequest.getEmail()));
        } catch (BadCredentialsException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }

        if(auth != null) {
            return ResponseEntity.ok(new JwtResponse(jwtUtil.generateToken(auth)));
        }
        return null;
    }

    @PostMapping(value = refreshToken)
    public ResponseEntity<JwtResponse> refreshToken(HttpServletRequest request) {
        // From the HttpRequest get the claims with the expired token details
        Claims claims = (Claims) request.getAttribute("claims");
        return ResponseEntity.ok(new JwtResponse(jwtUtil.generateRefreshToken(claims)));
    }

}
