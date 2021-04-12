package com.irene.authentication.providers;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
@Setter
public class AuthenticationToken extends UsernamePasswordAuthenticationToken {

    private String email;

    public AuthenticationToken(Object principal, Object credentials, String email) {
        super(principal, credentials);
        this.email = email;
    }

    public AuthenticationToken(Object principal, Object credentials, String email, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
        this.email = email;
    }

}
