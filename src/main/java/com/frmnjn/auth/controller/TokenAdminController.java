package com.frmnjn.auth.controller;

import com.frmnjn.auth.dto.BulkRevokeRequest;
import com.frmnjn.auth.dto.BulkUserRevokeRequest;
import com.frmnjn.auth.dto.SessionIdentifier;
import com.frmnjn.auth.service.AuthService;
import com.frmnjn.auth.service.MultiTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/admin/tokens")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Log4j2
public class TokenAdminController {

  private final AuthService authService;
  private final MultiTokenService multiTokenService;

  // ==================== INDIVIDUAL TOKEN REVOCATION ====================

  @PostMapping("/revoke/access")
  public ResponseEntity<Map<String, Object>> revokeAccessToken(
      @RequestParam String username,
      @RequestParam String sessionId) {

    log.info("Admin revoking access token for user: {} session: {}", username, sessionId);

    try {
      // Check if session exists first
      if (!multiTokenService.sessionExists(username, sessionId)) {
        return ResponseEntity.badRequest().body(createResponse(false,
            "Session not found for user: " + username, null));
      }

      // Revoke only access token, keep refresh token
      String accessKey = "access_token:" + username + ":" + sessionId;
      multiTokenService.revokeSpecificToken(accessKey);

      Map<String, Object> data = new HashMap<>();
      data.put("username", username);
      data.put("sessionId", sessionId);
      data.put("tokenType", "access");

      return ResponseEntity.ok(createResponse(true,
          "Access token revoked for user: " + username + " session: " + sessionId, data));

    } catch (Exception e) {
      log.error("Failed to revoke access token for user: {} session: {}", username, sessionId, e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed to revoke access token: " + e.getMessage(), null));
    }
  }

  @PostMapping("/revoke/refresh")
  public ResponseEntity<Map<String, Object>> revokeRefreshToken(
      @RequestParam String username,
      @RequestParam String sessionId) {

    log.info("Admin revoking refresh token for user: {} session: {}", username, sessionId);

    try {
      if (!multiTokenService.sessionExists(username, sessionId)) {
        return ResponseEntity.badRequest().body(createResponse(false,
            "Session not found for user: " + username, null));
      }

      // Revoke only refresh token, keep access token until it expires naturally
      String refreshKey = "refresh_token:" + username + ":" + sessionId;
      multiTokenService.revokeSpecificToken(refreshKey);

      Map<String, Object> data = new HashMap<>();
      data.put("username", username);
      data.put("sessionId", sessionId);
      data.put("tokenType", "refresh");
      data.put("note", "Access token remains valid until expiry");

      return ResponseEntity.ok(createResponse(true,
          "Refresh token revoked for user: " + username + " session: " + sessionId, data));

    } catch (Exception e) {
      log.error("Failed to revoke refresh token for user: {} session: {}", username, sessionId, e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed to revoke refresh token: " + e.getMessage(), null));
    }
  }

  // ==================== SESSION MANAGEMENT ====================

  @PostMapping("/revoke/session")
  public ResponseEntity<Map<String, Object>> revokeSession(
      @RequestParam String username,
      @RequestParam String sessionId) {

    log.info("Admin revoking entire session for user: {} session: {}", username, sessionId);

    try {
      if (!multiTokenService.sessionExists(username, sessionId)) {
        return ResponseEntity.badRequest().body(createResponse(false,
            "Session not found for user: " + username, null));
      }

      // Revoke both access and refresh tokens for this session
      multiTokenService.revokeSession(username, sessionId);

      Map<String, Object> data = new HashMap<>();
      data.put("username", username);
      data.put("sessionId", sessionId);
      data.put("tokensRevoked", "both access and refresh tokens");

      return ResponseEntity.ok(createResponse(true,
          "Session revoked for user: " + username + " session: " + sessionId, data));

    } catch (Exception e) {
      log.error("Failed to revoke session for user: {} session: {}", username, sessionId, e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed to revoke session: " + e.getMessage(), null));
    }
  }

  @PostMapping("/revoke/user/all")
  public ResponseEntity<Map<String, Object>> revokeAllUserSessions(@RequestParam String username) {

    log.info("Admin revoking ALL sessions for user: {}", username);

    try {
      Set<String> activeSessions = multiTokenService.getActiveSessions(username);
      int sessionCount = activeSessions != null ? activeSessions.size() : 0;

      if (sessionCount == 0) {
        return ResponseEntity.badRequest().body(createResponse(false,
            "No active sessions found for user: " + username, null));
      }

      // Revoke all sessions (logout from all devices)
      multiTokenService.revokeAllSessions(username);

      Map<String, Object> data = new HashMap<>();
      data.put("username", username);
      data.put("sessionsRevoked", sessionCount);
      data.put("revokedSessions", activeSessions);

      return ResponseEntity.ok(createResponse(true,
          "All " + sessionCount + " sessions revoked for user: " + username, data));

    } catch (Exception e) {
      log.error("Failed to revoke all sessions for user: {}", username, e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed to revoke all sessions: " + e.getMessage(), null));
    }
  }

  // ==================== BULK OPERATIONS ====================

  @PostMapping("/revoke/bulk/sessions")
  public ResponseEntity<Map<String, Object>> revokeBulkSessions(@RequestBody BulkRevokeRequest request) {

    log.info("Admin performing bulk session revocation for {} entries", request.getSessions().size());

    try {
      Map<String, String> results = new HashMap<>();
      int successCount = 0;
      int failureCount = 0;

      for (SessionIdentifier session : request.getSessions()) {
        try {
          if (multiTokenService.sessionExists(session.getUsername(), session.getSessionId())) {
            multiTokenService.revokeSession(session.getUsername(), session.getSessionId());
            results.put(session.getUsername() + ":" + session.getSessionId(), "SUCCESS");
            successCount++;
          } else {
            results.put(session.getUsername() + ":" + session.getSessionId(), "SESSION_NOT_FOUND");
            failureCount++;
          }
        } catch (Exception e) {
          results.put(session.getUsername() + ":" + session.getSessionId(), "ERROR: " + e.getMessage());
          failureCount++;
        }
      }

      Map<String, Object> data = new HashMap<>();
      data.put("totalRequested", request.getSessions().size());
      data.put("successful", successCount);
      data.put("failed", failureCount);
      data.put("details", results);

      return ResponseEntity.ok(createResponse(true,
          "Bulk revocation completed: " + successCount + " successful, " + failureCount + " failed", data));

    } catch (Exception e) {
      log.error("Failed to perform bulk session revocation", e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed to perform bulk revocation: " + e.getMessage(), null));
    }
  }

  @PostMapping("/revoke/bulk/users")
  public ResponseEntity<Map<String, Object>> revokeBulkUsers(@RequestBody BulkUserRevokeRequest request) {

    log.info("Admin revoking all sessions for {} users", request.getUsernames().size());

    try {
      Map<String, Object> results = new HashMap<>();
      int totalSessionsRevoked = 0;

      for (String username : request.getUsernames()) {
        try {
          Set<String> activeSessions = multiTokenService.getActiveSessions(username);
          int sessionCount = activeSessions != null ? activeSessions.size() : 0;

          if (sessionCount > 0) {
            multiTokenService.revokeAllSessions(username);
            results.put(username, sessionCount + " sessions revoked");
            totalSessionsRevoked += sessionCount;
          } else {
            results.put(username, "No active sessions");
          }
        } catch (Exception e) {
          results.put(username, "ERROR: " + e.getMessage());
        }
      }

      Map<String, Object> data = new HashMap<>();
      data.put("totalUsers", request.getUsernames().size());
      data.put("totalSessionsRevoked", totalSessionsRevoked);
      data.put("userResults", results);

      return ResponseEntity.ok(createResponse(true,
          "Bulk user revocation completed: " + totalSessionsRevoked + " total sessions revoked", data));

    } catch (Exception e) {
      log.error("Failed to perform bulk user revocation", e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed to perform bulk user revocation: " + e.getMessage(), null));
    }
  }

  // ==================== TOKEN VALIDATION ====================

  @GetMapping("/validate/access")
  public ResponseEntity<Map<String, Object>> validateAccessToken(
      @RequestParam String username,
      @RequestParam String sessionId,
      @RequestParam String token) {

    try {
      boolean isValid = authService.isAccessTokenValid(username, sessionId, token);
      long ttl = multiTokenService.getAccessTokenTtl(username, sessionId);

      Map<String, Object> data = new HashMap<>();
      data.put("username", username);
      data.put("sessionId", sessionId);
      data.put("tokenType", "access");
      data.put("isValid", isValid);
      data.put("ttlSeconds", ttl);

      return ResponseEntity.ok(createResponse(true,
          "Access token validation completed", data));

    } catch (Exception e) {
      log.error("Failed to validate access token for user: {} session: {}", username, sessionId, e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed to validate access token: " + e.getMessage(), null));
    }
  }

  @GetMapping("/validate/refresh")
  public ResponseEntity<Map<String, Object>> validateRefreshToken(
      @RequestParam String username,
      @RequestParam String sessionId,
      @RequestParam String token) {

    try {
      boolean isValid = authService.isRefreshTokenValid(username, sessionId, token);
      long ttl = multiTokenService.getRefreshTokenTtl(username, sessionId);

      Map<String, Object> data = new HashMap<>();
      data.put("username", username);
      data.put("sessionId", sessionId);
      data.put("tokenType", "refresh");
      data.put("isValid", isValid);
      data.put("ttlSeconds", ttl);

      return ResponseEntity.ok(createResponse(true,
          "Refresh token validation completed", data));

    } catch (Exception e) {
      log.error("Failed to validate refresh token for user: {} session: {}", username, sessionId, e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed to validate refresh token: " + e.getMessage(), null));
    }
  }

  @GetMapping("/validate/pair")
  public ResponseEntity<Map<String, Object>> validateTokenPair(
      @RequestParam String username,
      @RequestParam String sessionId,
      @RequestParam String accessToken,
      @RequestParam String refreshToken) {

    try {
      boolean areTied = authService.areTokensTied(username, sessionId, accessToken, refreshToken);

      Map<String, Object> data = new HashMap<>();
      data.put("username", username);
      data.put("sessionId", sessionId);
      data.put("areTied", areTied);
      data.put("accessTokenValid", authService.isAccessTokenValid(username, sessionId, accessToken));
      data.put("refreshTokenValid", authService.isRefreshTokenValid(username, sessionId, refreshToken));

      return ResponseEntity.ok(createResponse(true,
          "Token pair validation completed", data));

    } catch (Exception e) {
      log.error("Failed to validate token pair for user: {} session: {}", username, sessionId, e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed to validate token pair: " + e.getMessage(), null));
    }
  }

  // ==================== SESSION MONITORING ====================

  @GetMapping("/sessions/user/{username}")
  public ResponseEntity<Map<String, Object>> getUserSessions(@PathVariable String username) {
    try {
      Set<String> activeSessions = multiTokenService.getActiveSessions(username);

      Map<String, Object> sessionDetails = new HashMap<>();
      if (activeSessions != null) {
        for (String sessionId : activeSessions) {
          Map<String, Object> sessionInfo = new HashMap<>();
          sessionInfo.put("accessTokenTtl", multiTokenService.getAccessTokenTtl(username, sessionId));
          sessionInfo.put("refreshTokenTtl", multiTokenService.getRefreshTokenTtl(username, sessionId));
          sessionDetails.put(sessionId, sessionInfo);
        }
      }

      Map<String, Object> data = new HashMap<>();
      data.put("username", username);
      data.put("activeSessionCount", activeSessions != null ? activeSessions.size() : 0);
      data.put("sessions", sessionDetails);

      return ResponseEntity.ok(createResponse(true,
          "User sessions retrieved", data));

    } catch (Exception e) {
      log.error("Failed to get sessions for user: {}", username, e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed to get user sessions: " + e.getMessage(), null));
    }
  }

  @GetMapping("/sessions/all")
  public ResponseEntity<Map<String, Object>> getAllActiveSessions() {
    try {
      // This would require additional tracking in Redis or database
      // For now, return a message about implementing this feature

      Map<String, Object> data = new HashMap<>();
      data.put("note", "This feature requires additional implementation to track all active sessions across all users");
      data.put("recommendation", "Use getUserSessions endpoint for specific users");

      return ResponseEntity.ok(createResponse(true,
          "Get all active sessions - Feature not implemented", data));

    } catch (Exception e) {
      log.error("Failed to get all active sessions", e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed to get all active sessions: " + e.getMessage(), null));
    }
  }

  // ==================== EMERGENCY OPERATIONS ====================

  @PostMapping("/emergency/revoke-all")
  @PreAuthorize("hasRole('SUPER_ADMIN')")
  public ResponseEntity<Map<String, Object>> emergencyRevokeAll(@RequestParam String confirmationCode) {

    // Add confirmation code check for safety
    if (!"EMERGENCY_REVOKE_ALL_TOKENS".equals(confirmationCode)) {
      return ResponseEntity.badRequest().body(createResponse(false,
          "Invalid confirmation code", null));
    }

    log.warn("EMERGENCY: Revoking ALL tokens system-wide");

    try {
      // This would require scanning all Redis keys with the token prefixes
      // Implementation depends on your Redis setup and performance requirements

      Map<String, Object> data = new HashMap<>();
      data.put("warning", "This operation is not implemented for safety reasons");
      data.put("note", "Use bulk operations or individual user revocation instead");

      return ResponseEntity.ok(createResponse(true,
          "Emergency revoke all - Not implemented for safety", data));

    } catch (Exception e) {
      log.error("Failed emergency revoke all", e);
      return ResponseEntity.internalServerError().body(createResponse(false,
          "Failed emergency revoke all: " + e.getMessage(), null));
    }
  }

  // ==================== UTILITY METHODS ====================

  private Map<String, Object> createResponse(boolean success, String message, Object data) {
    Map<String, Object> response = new HashMap<>();
    response.put("success", success);
    response.put("message", message);
    response.put("timestamp", System.currentTimeMillis());
    if (data != null) {
      response.put("data", data);
    }
    return response;
  }
}

// ==================== REQUEST DTOs ====================

