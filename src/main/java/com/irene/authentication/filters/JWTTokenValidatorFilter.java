package com.irene.authentication.filters;

import com.irene.authentication.controller.AuthController;
import com.irene.authentication.utils.JwtUtil;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
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

public class JWTTokenValidatorFilter extends OncePerRequestFilter {

	private final String PREFIX = "Bearer ";

	@Autowired
	private JwtUtil jwtUtil;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException, ExpiredJwtException, UnsupportedJwtException, MalformedJwtException {
		String jwt = request.getHeader(HttpHeaders.AUTHORIZATION);

		if (null != jwt) {
			try {
				SecretKey key = jwtUtil.getKey();
				Claims claims = Jwts.parserBuilder()
						.setSigningKey(key)
						.build()
						.parseClaimsJws(jwt.replace(PREFIX, ""))
						.getBody();

				String subject = String.valueOf(claims.get("sub"));
				String roles = (String) claims.get(JwtUtil.AUTHORITIES_KEY);
				Authentication auth = new UsernamePasswordAuthenticationToken(subject,null,
						AuthorityUtils.commaSeparatedStringToAuthorityList(roles));

				//Sets the authentication in the Spring flow
				SecurityContextHolder.getContext().setAuthentication(auth);
			} catch (ExpiredJwtException e) {

				String requestURL = request.getRequestURL().toString();
				// allow for Refresh Token creation if following conditions are true.
				if (jwt != null && requestURL.contains(AuthController.refreshToken)) {
					allowForRefreshToken(e, request);
				} else {
					request.setAttribute("exception", e);
				}

			} catch (UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
				request.setAttribute("exception", e);
				throw e;
			}

		}
		chain.doFilter(request, response);
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return request.getServletPath().equals(AuthController.token);
	}

	private void allowForRefreshToken(ExpiredJwtException ex, HttpServletRequest request) {

		// create a UsernamePasswordAuthenticationToken with null values.
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
				null, null, null);
		// After setting the Authentication in the context, we specify
		// that the current user is authenticated. So it passes the
		// Spring Security Configurations successfully.
		SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
		// Set the claims so that in controller we will be using it to create
		// new JWT
		request.setAttribute("claims", ex.getClaims());
	}

}
