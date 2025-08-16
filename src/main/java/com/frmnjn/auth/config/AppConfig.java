package com.frmnjn.auth.config;

import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.util.Base64;

@Configuration
public class AppConfig {
  @Value("${security.jwt.secret}")
  private String secretKey;

  @Bean
  public SecretKey getSignInKey() {
    byte[] keyBytes = Base64.getEncoder().encode(secretKey.getBytes());
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
