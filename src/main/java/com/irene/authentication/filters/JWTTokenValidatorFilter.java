package com.irene.authentication.filters;

import com.irene.authentication.controller.AuthController;
import com.irene.authentication.utils.JwtUtil;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class JWTTokenValidatorFilter extends OncePerRequestFilter {

	private final String PREFIX = "Bearer ";
	private static final String AUTHORITIES_KEY = "authorities";
	@Value("${jwt.secret-key}")
	private String secretKey;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException, ExpiredJwtException, UnsupportedJwtException, MalformedJwtException {
		String jwt = request.getHeader(HttpHeaders.AUTHORIZATION);

		if (jwt == null) {
			anonymousAuthentication();
			chain.doFilter(request, response);
			return;
		}

		jwt = jwt.replace(PREFIX, "").replace(PREFIX.strip(), "");
		if (jwt.isBlank() || jwt.equals("null")) {
			anonymousAuthentication();
			chain.doFilter(request, response);
			return;
		}

		try {
			Claims claims = Jwts.parserBuilder()
					.setSigningKey(getKey())
					.build()
					.parseClaimsJws(jwt)
					.getBody();

			Object principal = claims.get("sub");
			ArrayList roles = (ArrayList) claims.get(AUTHORITIES_KEY);
			Authentication auth = new UsernamePasswordAuthenticationToken(principal,null,
					AuthorityUtils.commaSeparatedStringToAuthorityList(String.join(",", roles)));

			//Sets the authentication in the Spring flow
			SecurityContextHolder.getContext().setAuthentication(auth);
		} catch (ExpiredJwtException e) {

			String requestURL = request.getRequestURL().toString();
			// allow for Refresh Token creation if following conditions are true.
			if (jwt != null && requestURL.contains(AuthController.REFRESH_TOKEN)) {
				//request.setAttribute("auth", ex.getClaims());
				allowForRefreshToken(e, request);
			} else {
				request.setAttribute("exception", e);
			}
		} catch (UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
			request.setAttribute("exception", e);
			throw e;
		}
		chain.doFilter(request, response);
	}

	private SecretKey getKey() {
		return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
	}

	private void allowForRefreshToken(ExpiredJwtException ex, HttpServletRequest request) {

		// create a UsernamePasswordAuthenticationToken with null values.
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
				"RefreshTokenAuthentication", null, null);
		// After setting the Authentication in the context, we specify
		// that the current user is authenticated. So it passes the
		// Spring Security Configurations successfully.
		SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
		// Set the claims so that in controller we will be using it to create
		// new JWT
		request.setAttribute("claims", ex.getClaims());
	}

	private void anonymousAuthentication() {
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken(null, null, null));
	}

}
