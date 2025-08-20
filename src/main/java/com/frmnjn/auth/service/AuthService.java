package com.frmnjn.auth.service;

import com.frmnjn.auth.dto.AuthResponse;
import com.frmnjn.auth.dto.RegisterRequest;
import com.frmnjn.auth.exception.AuthException;
import com.frmnjn.auth.exception.RegisterFailedException;
import com.frmnjn.auth.model.auth.Role;
import com.frmnjn.auth.model.auth.UserData;
import com.frmnjn.auth.repository.RoleRepository;
import com.frmnjn.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

  private final AuthenticationManager authenticationManager;
  private final JwtService jwtService;
  private final UserInfoService userInfoService;
  private final UserRepository userRepository;
  private final RoleRepository roleRepository;
  private final PasswordEncoder passwordEncoder;
  private final MultiTokenService multiTokenService;

  private static final long REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60L; // 7 days
  private static final long ACCESS_TOKEN_TTL = 15 * 60L; // 15 minutes

  public AuthResponse login(String username, String password, Map<String, String> deviceInfo) {
    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    var userDetails = userInfoService.loadUserByUsername(username);
    return buildAuthResponse(userDetails.getUsername(), deviceInfo);
  }

  public AuthResponse register(RegisterRequest request, Map<String, String> deviceInfo) {
    if (userRepository.findByUsername(request.getUsername()).isPresent()) {
      throw new RegisterFailedException("Username already exists");
    }

    Role defaultRole = roleRepository.findByName("user")
        .orElseThrow(() -> new RegisterFailedException("Default role not found"));

    UserData newUser = new UserData();
    newUser.setUsername(request.getUsername());
    newUser.setPasswordHash(passwordEncoder.encode(request.getPassword()));
    newUser.setEmail(request.getEmail());
    newUser.setIsActive(true);
    newUser.setRole(defaultRole);

    userRepository.save(newUser);

    return buildAuthResponse(newUser.getUsername(), deviceInfo);
  }

  public AuthResponse refreshToken(String refreshToken, String sessionId) {
    String username = jwtService.extractUsername(refreshToken);

    userRepository.findByUsername(username)
        .orElseThrow(() -> new AuthException("User not found"));

    if (!jwtService.isTokenValid(refreshToken, username)) {
      throw new AuthException("Invalid refresh token");
    }

    // CRITICAL: Check that refresh token belongs to THIS specific session
    // This prevents refresh_token_b from being used to renew access_token_a
    if (!multiTokenService.canRefreshWithSession(username, sessionId, refreshToken)) {
      throw new AuthException("Refresh token does not belong to this session or has been revoked");
    }

    // Generate new tokens for the SAME session (tied together)
    String newAccessToken = jwtService.generateToken(username, sessionId);
    String newRefreshToken = jwtService.generateRefreshToken(username, sessionId);

    // Store new token pair for the same session - they remain tied
    multiTokenService.storeTokenPair(username, sessionId, newAccessToken, newRefreshToken,
        ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL);

    AuthResponse authResponse = new AuthResponse();
    authResponse.setAccessToken(newAccessToken);
    authResponse.setRefreshToken(newRefreshToken);
    authResponse.setSessionId(sessionId); // Same session ID - tokens remain tied
    return authResponse;
  }

  // Logout specific session
  public void logout(String username, String sessionId) {
    multiTokenService.revokeSession(username, sessionId);
  }

  // Logout all sessions
  public void logoutAllSessions(String username) {
    multiTokenService.revokeAllSessions(username);
  }

  public boolean isAccessTokenValid(String username, String sessionId, String accessToken) {
    return jwtService.isTokenValid(accessToken, username, sessionId) &&
        multiTokenService.validateAccessToken(username, sessionId, accessToken);
  }

  public boolean isRefreshTokenValid(String username, String sessionId, String refreshToken) {
    return jwtService.isTokenValid(refreshToken, username, sessionId) &&
        multiTokenService.validateRefreshToken(username, sessionId, refreshToken);
  }

  // Validate that both tokens belong to the same session (are tied together)
  public boolean areTokensTied(String username, String sessionId, String accessToken, String refreshToken) {
    return jwtService.isTokenValid(accessToken, username, sessionId) &&
        jwtService.isTokenValid(refreshToken, username, sessionId) &&
        multiTokenService.validateTokenPair(username, sessionId, accessToken, refreshToken);
  }

  private AuthResponse buildAuthResponse(String username, Map<String, String> deviceInfo) {
    // Generate a new session ID - this ties the tokens together
    String sessionId = multiTokenService.generateSessionId();
    String accessToken = jwtService.generateToken(username, sessionId); // Include session ID
    String refreshToken = jwtService.generateRefreshToken(username, sessionId); // Include session ID

    // Store both tokens as a TIED PAIR for this session/device
    multiTokenService.storeTokenPair(username, sessionId, accessToken, refreshToken,
        ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL);

    AuthResponse authResponse = new AuthResponse();
    authResponse.setAccessToken(accessToken);
    authResponse.setRefreshToken(refreshToken);
    authResponse.setSessionId(sessionId); // Client MUST store and send this with requests
    authResponse.setDeviceInfo(deviceInfo);
    return authResponse;
  }
}