package com.frmnjn.auth.controller;

import com.frmnjn.auth.dto.AuthResponse;
import com.frmnjn.auth.dto.LoginRequest;
import com.frmnjn.auth.dto.RefreshTokenRequest;
import com.frmnjn.auth.dto.RegisterRequest;
import com.frmnjn.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  @PostMapping("/login")
  public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
    // Extract device info from headers or user agent
    Map<String, String> deviceInfo = extractDeviceInfo(httpRequest);

    AuthResponse response = authService.login(request.getUsername(), request.getPassword(), deviceInfo);

    // Each login creates a NEW session with tied tokens
    // Device A gets: sessionId_A, access_token_A, refresh_token_A
    // Device B gets: sessionId_B, access_token_B, refresh_token_B
    return ResponseEntity.ok(response);
  }

  @PostMapping("/register")
  public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
    Map<String, String> deviceInfo = extractDeviceInfo(httpRequest);
    AuthResponse response = authService.register(request, deviceInfo);
    return ResponseEntity.ok(response);
  }

  @PostMapping("/refresh")
  public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
    // CLIENT MUST SEND:
    // 1. refresh_token (refresh_token_A or refresh_token_B)
    // 2. session_id (sessionId_A or sessionId_B)
    //
    // VALIDATION:
    // - refresh_token_A can ONLY be used with sessionId_A
    // - refresh_token_B can ONLY be used with sessionId_B
    // - Cross-session usage will fail

    AuthResponse response = authService.refreshToken(request.getRefreshToken(), request.getSessionId());
    return ResponseEntity.ok(response);
  }

  @PostMapping("/logout")
  public ResponseEntity<String> logout(@RequestParam String username, @RequestParam String sessionId) {
    // Logout specific session/device
    // This only revokes tokens for THIS session, other devices remain logged in
    authService.logout(username, sessionId);
    return ResponseEntity.ok("Successfully logged out from this device");
  }

  @PostMapping("/logout-all")
  public ResponseEntity<String> logoutAll(@RequestParam String username) {
    // Logout from ALL devices/sessions
    authService.logoutAllSessions(username);
    return ResponseEntity.ok("Successfully logged out from all devices");
  }

  private Map<String, String> extractDeviceInfo(HttpServletRequest request) {
    String userAgent = request.getHeader("User-Agent");
    String deviceId = request.getHeader("X-Device-ID"); // Custom header from client
    String deviceType = request.getHeader("X-Device-Type"); // mobile, web, desktop

    Map<String, String> deviceInfo = new HashMap<>();
    deviceInfo.put("userAgent", userAgent);
    deviceInfo.put("deviceId", deviceId);
    deviceInfo.put("deviceType", deviceType);

    return deviceInfo;
  }
}

