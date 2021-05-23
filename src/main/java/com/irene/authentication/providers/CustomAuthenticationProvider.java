package com.irene.authentication.providers;

import io.netty.util.internal.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationProvider.class);

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        AuthenticationToken auth = (AuthenticationToken) authentication;

        if(StringUtil.isNullOrEmpty(auth.getEmail()))
            return null;
        logger.debug("Authenticating custom user.");

        return new AuthenticationToken(auth.getPrincipal(), null, auth.getEmail(),
                Arrays.asList(new SimpleGrantedAuthority("ROLE_CUSTOM")));

       //throw new BadCredentialsException("External system authentication failed.");
    }

    @Override
    public boolean supports(Class<?> auth) {
        return auth.equals(AuthenticationToken.class);
    }

}
