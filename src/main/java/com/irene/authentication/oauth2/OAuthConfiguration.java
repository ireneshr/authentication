package com.irene.authentication.oauth2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * This class enables client_credentials authorization with Oauth2
 */
@Configuration
@EnableAuthorizationServer
public class OAuthConfiguration extends AuthorizationServerConfigurerAdapter {

   private final AuthenticationManager authenticationManager;
   private final PasswordEncoder passwordEncoder;

   @Value("${oauth2.client-id}")
   private String clientId;
   @Value("${oauth2.client-secret}")
   private String clientSecret;
   @Value("${oauth2.authorized-grant-types}")
   private String[] authorizedGrantTypes;
   @Value("${oauth2.expiry-time-in-h}")
   private int expiryTime;
   @Value("${oauth2.refresh-expiry-time-in-h}")
   private int refreshExpiryTime;
   @Value("${jwt.secret-key}")
   private String signingKey;

   public OAuthConfiguration(AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder) {
       this.authenticationManager = authenticationManager;
       this.passwordEncoder = passwordEncoder;
   }

   @Override
   public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
       clients.inMemory()
               .withClient(clientId)
               .secret(passwordEncoder.encode(clientSecret))
               .authorities("ROLE_MICROSERVICE")
               .accessTokenValiditySeconds((int) TimeUnit.HOURS.toSeconds(expiryTime))
               .refreshTokenValiditySeconds((int) TimeUnit.HOURS.toSeconds(refreshExpiryTime))
               .authorizedGrantTypes(authorizedGrantTypes)
               .scopes("read", "write");
   }

   @Override
   public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
      TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
      tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), accessTokenConverter()));

      endpoints
              .tokenStore(tokenStore())
              .tokenEnhancer(tokenEnhancerChain)
              .authenticationManager(authenticationManager);
   }

   @Bean
   public JwtAccessTokenConverter accessTokenConverter() {
      JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
      converter.setSigningKey(signingKey);
      return converter;
   }

   @Bean
   public TokenStore tokenStore() {
      return new JwtTokenStore(accessTokenConverter());
   }

   @Bean
   public TokenEnhancer tokenEnhancer() {
      return new CustomTokenEnhancer();
   }

}
