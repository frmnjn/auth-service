package com.frmnjn.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

  @Value("${security.jwt.expiration:900000}") // 15 minutes default
  private long jwtExpiration;

  @Value("${security.jwt.refresh-expiration:604800000}") // 7 days default
  private long refreshExpiration;

  private final SecretKey secretKey;

  public JwtService(SecretKey secretKey) {
    this.secretKey = secretKey;
  }

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public String extractSessionId(String token) {
    return extractClaim(token, claims -> claims.get("sessionId", String.class));
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public String generateToken(String username, String sessionId) {
    return generateToken(new HashMap<>(), username, sessionId);
  }

  public String generateToken(Map<String, Object> extraClaims, String username, String sessionId) {
    return buildToken(extraClaims, username, sessionId, jwtExpiration);
  }

  public String generateRefreshToken(String username, String sessionId) {
    return buildToken(new HashMap<>(), username, sessionId, refreshExpiration);
  }

  private String buildToken(
      Map<String, Object> extraClaims,
      String username,
      String sessionId,
      long expiration
  ) {
    return Jwts
        .builder()
        .claims(extraClaims)
        .subject(username)
        .claim("sessionId", sessionId) // Embed session ID in JWT
        .issuedAt(new Date(System.currentTimeMillis()))
        .expiration(new Date(System.currentTimeMillis() + expiration))
        .signWith(secretKey)
        .compact();
  }

  public boolean isTokenValid(String token, String username) {
    final String extractedUsername = extractUsername(token);
    return (extractedUsername.equals(username)) && !isTokenExpired(token);
  }

  public boolean isTokenValid(String token, String username, String sessionId) {
    final String extractedUsername = extractUsername(token);
    final String extractedSessionId = extractSessionId(token);
    return (extractedUsername.equals(username)) &&
        (extractedSessionId != null && extractedSessionId.equals(sessionId)) &&
        !isTokenExpired(token);
  }

  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  private Claims extractAllClaims(String token) {
    return Jwts
        .parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }
}