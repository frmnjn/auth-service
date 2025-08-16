package com.frmnjn.auth.service;

import com.frmnjn.auth.exception.TokenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Log4j2
public class MultiTokenService {

  private final RedisTemplate<String, String> redisTemplate;

  private static final String ACCESS_TOKEN_PREFIX = "access_token:";
  private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
  private static final String USER_SESSIONS_PREFIX = "user_sessions:";
  private static final int MAX_SESSIONS_PER_USER = 5; // Limit concurrent sessions

  public String generateSessionId() {
    return UUID.randomUUID().toString();
  }

  // Store both tokens as a tied pair for a session/device
  public void storeTokenPair(String username, String sessionId, String accessToken, String refreshToken,
                             long accessTtl, long refreshTtl) {
    String accessKey = ACCESS_TOKEN_PREFIX + username + ":" + sessionId;
    String refreshKey = REFRESH_TOKEN_PREFIX + username + ":" + sessionId;
    String sessionKey = USER_SESSIONS_PREFIX + username;

    try {
      // Store both tokens tied to the same session
      redisTemplate.opsForValue().set(accessKey, accessToken, accessTtl, TimeUnit.SECONDS);
      redisTemplate.opsForValue().set(refreshKey, refreshToken, refreshTtl, TimeUnit.SECONDS);

      // Track this session for the user
      redisTemplate.opsForSet().add(sessionKey, sessionId);
      redisTemplate.expire(sessionKey, refreshTtl, TimeUnit.SECONDS); // Session expires with refresh token

      // Cleanup old sessions if exceeding limit
      cleanupOldSessions(username);

      log.info("Token pair stored for user: {} with session: {}", username, sessionId);
    } catch (Exception e) {
      log.error("Failed to store token pair for user: {} session: {}", username, sessionId, e);
      throw new TokenException("Failed to store token pair", e);
    }
  }

  // Store access token with session ID (for individual updates)
  public void storeAccessToken(String username, String sessionId, String token, long ttlSeconds) {
    String tokenKey = ACCESS_TOKEN_PREFIX + username + ":" + sessionId;

    try {
      redisTemplate.opsForValue().set(tokenKey, token, ttlSeconds, TimeUnit.SECONDS);
      log.info("Access token updated for user: {} with session: {}", username, sessionId);
    } catch (Exception e) {
      log.error("Failed to store access token for user: {} session: {}", username, sessionId, e);
      throw new TokenException("Failed to store access token", e);
    }
  }

  // Individual token validation methods
  public boolean validateAccessToken(String username, String sessionId, String token) {
    String key = ACCESS_TOKEN_PREFIX + username + ":" + sessionId;
    try {
      String storedToken = redisTemplate.opsForValue().get(key);
      return storedToken != null && storedToken.equals(token);
    } catch (Exception e) {
      log.error("Failed to validate access token for user: {} session: {}", username, sessionId, e);
      return false;
    }
  }

  public boolean validateRefreshToken(String username, String sessionId, String token) {
    String key = REFRESH_TOKEN_PREFIX + username + ":" + sessionId;
    try {
      String storedToken = redisTemplate.opsForValue().get(key);
      return storedToken != null && storedToken.equals(token);
    } catch (Exception e) {
      log.error("Failed to validate refresh token for user: {} session: {}", username, sessionId, e);
      return false;
    }
  }

  // Validate that refresh token belongs to the same session as access token
  public boolean validateTokenPair(String username, String sessionId, String accessToken, String refreshToken) {
    String accessKey = ACCESS_TOKEN_PREFIX + username + ":" + sessionId;
    String refreshKey = REFRESH_TOKEN_PREFIX + username + ":" + sessionId;

    try {
      String storedAccessToken = redisTemplate.opsForValue().get(accessKey);
      String storedRefreshToken = redisTemplate.opsForValue().get(refreshKey);

      boolean accessValid = storedAccessToken != null && storedAccessToken.equals(accessToken);
      boolean refreshValid = storedRefreshToken != null && storedRefreshToken.equals(refreshToken);

      log.info("Token pair validation for user: {} session: {} - Access: {}, Refresh: {}",
          username, sessionId, accessValid, refreshValid);

      return accessValid && refreshValid;
    } catch (Exception e) {
      log.error("Failed to validate token pair for user: {} session: {}", username, sessionId, e);
      return false;
    }
  }

  // Check if refresh token exists and is valid for this specific session
  public boolean canRefreshWithSession(String username, String sessionId, String refreshToken) {
    String refreshKey = REFRESH_TOKEN_PREFIX + username + ":" + sessionId;

    try {
      String storedRefreshToken = redisTemplate.opsForValue().get(refreshKey);
      boolean isValid = storedRefreshToken != null && storedRefreshToken.equals(refreshToken);

      log.info("Refresh validation for user: {} session: {} - Valid: {}", username, sessionId, isValid);
      return isValid;
    } catch (Exception e) {
      log.error("Failed to validate refresh capability for user: {} session: {}", username, sessionId, e);
      return false;
    }
  }

  // Revoke specific session tokens
  public void revokeSession(String username, String sessionId) {
    try {
      String accessKey = ACCESS_TOKEN_PREFIX + username + ":" + sessionId;
      String refreshKey = REFRESH_TOKEN_PREFIX + username + ":" + sessionId;
      String sessionKey = USER_SESSIONS_PREFIX + username;

      redisTemplate.delete(accessKey);
      redisTemplate.delete(refreshKey);
      redisTemplate.opsForSet().remove(sessionKey, sessionId);

      log.info("Session revoked for user: {} session: {}", username, sessionId);
    } catch (Exception e) {
      log.error("Failed to revoke session for user: {} session: {}", username, sessionId, e);
    }
  }

  // Revoke all sessions for a user
  public void revokeAllSessions(String username) {
    try {
      String sessionKey = USER_SESSIONS_PREFIX + username;
      Set<String> sessions = redisTemplate.opsForSet().members(sessionKey);

      if (sessions != null) {
        for (String sessionId : sessions) {
          String accessKey = ACCESS_TOKEN_PREFIX + username + ":" + sessionId;
          String refreshKey = REFRESH_TOKEN_PREFIX + username + ":" + sessionId;
          redisTemplate.delete(accessKey);
          redisTemplate.delete(refreshKey);
        }
      }

      redisTemplate.delete(sessionKey);
      log.info("All sessions revoked for user: {}", username);
    } catch (Exception e) {
      log.error("Failed to revoke all sessions for user: {}", username, e);
    }
  }

  // Get active sessions for a user
  public Set<String> getActiveSessions(String username) {
    String sessionKey = USER_SESSIONS_PREFIX + username;
    return redisTemplate.opsForSet().members(sessionKey);
  }

  // Check if session exists
  public boolean sessionExists(String username, String sessionId) {
    String sessionKey = USER_SESSIONS_PREFIX + username;
    return Boolean.TRUE.equals(redisTemplate.opsForSet().isMember(sessionKey, sessionId));
  }

  // Revoke specific token by key (used by admin controller)
  public void revokeSpecificToken(String tokenKey) {
    try {
      redisTemplate.delete(tokenKey);
      log.info("Specific token revoked: {}", tokenKey);
    } catch (Exception e) {
      log.error("Failed to revoke specific token: {}", tokenKey, e);
      throw new TokenException("Failed to revoke token", e);
    }
  }

  // Get token TTL
  public long getAccessTokenTtl(String username, String sessionId) {
    String key = ACCESS_TOKEN_PREFIX + username + ":" + sessionId;
    try {
      return redisTemplate.getExpire(key, TimeUnit.SECONDS);
    } catch (Exception e) {
      log.error("Failed to get access token TTL for user: {} session: {}", username, sessionId, e);
      return -1;
    }
  }

  public long getRefreshTokenTtl(String username, String sessionId) {
    String key = REFRESH_TOKEN_PREFIX + username + ":" + sessionId;
    try {
      return redisTemplate.getExpire(key, TimeUnit.SECONDS);
    } catch (Exception e) {
      log.error("Failed to get refresh token TTL for user: {} session: {}", username, sessionId, e);
      return -1;
    }
  }

  // Cleanup old sessions if user exceeds limit
  private void cleanupOldSessions(String username) {
    try {
      String sessionKey = USER_SESSIONS_PREFIX + username;
      Set<String> sessions = redisTemplate.opsForSet().members(sessionKey);

      if (sessions != null && sessions.size() > MAX_SESSIONS_PER_USER) {
        // Remove oldest sessions (this is simplified - you might want to track creation time)
        int sessionsToRemove = sessions.size() - MAX_SESSIONS_PER_USER;
        sessions.stream()
            .limit(sessionsToRemove)
            .forEach(sessionId -> revokeSession(username, sessionId));

        log.info("Cleaned up {} old sessions for user: {}", sessionsToRemove, username);
      }
    } catch (Exception e) {
      log.error("Failed to cleanup old sessions for user: {}", username, e);
    }
  }
}