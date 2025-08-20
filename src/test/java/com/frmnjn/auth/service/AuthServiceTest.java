package com.frmnjn.auth.service;

import com.frmnjn.auth.dto.AuthResponse;
import com.frmnjn.auth.dto.RegisterRequest;
import com.frmnjn.auth.exception.AuthException;
import com.frmnjn.auth.exception.RegisterFailedException;
import com.frmnjn.auth.model.auth.Role;
import com.frmnjn.auth.model.auth.UserData;
import com.frmnjn.auth.repository.RoleRepository;
import com.frmnjn.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

  @Mock
  private AuthenticationManager authenticationManager;
  @Mock
  private JwtService jwtService;
  @Mock
  private UserInfoService userInfoService;
  @Mock
  private UserRepository userRepository;
  @Mock
  private RoleRepository roleRepository;
  @Mock
  private PasswordEncoder passwordEncoder;
  @Mock
  private MultiTokenService multiTokenService;
  @InjectMocks
  private AuthService authService;

  private String username = "testuser";
  private String password = "password123";
  private String email = "test@example.com";
  private Map<String, String> deviceInfo = new HashMap<>();
  private String sessionId = "session123";
  private String accessToken = "accessToken";
  private String refreshToken = "refreshToken";

  @BeforeEach
  void setUp() {
    deviceInfo.put("device", "test-device");
  }

  @Test
  void login_Successful_ReturnsAuthResponse() {
    // Arrange
    UserDetails userDetails = mock(UserDetails.class);
    when(userInfoService.loadUserByUsername(username)).thenReturn(userDetails);
    when(userDetails.getUsername()).thenReturn(username);
    when(multiTokenService.generateSessionId()).thenReturn(sessionId);
    when(jwtService.generateToken(username, sessionId)).thenReturn(accessToken);
    when(jwtService.generateRefreshToken(username, sessionId)).thenReturn(refreshToken);

    // Act
    AuthResponse response = authService.login(username, password, deviceInfo);

    // Assert
    assertNotNull(response);
    assertEquals(accessToken, response.getAccessToken());
    assertEquals(refreshToken, response.getRefreshToken());
    assertEquals(sessionId, response.getSessionId());
    assertEquals(deviceInfo, response.getDeviceInfo());
    verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    verify(multiTokenService).storeTokenPair(anyString(), anyString(), anyString(), anyString(), anyLong(), anyLong());
  }

  @Test
  void register_NewUser_Successful() {
    // Arrange
    RegisterRequest request = new RegisterRequest();
    request.setUsername(username);
    request.setPassword(password);
    request.setEmail(email);

    Role role = new Role();
    role.setName("user");

    when(userRepository.findByUsername(username)).thenReturn(Optional.empty());
    when(roleRepository.findByName("user")).thenReturn(Optional.of(role));
    when(passwordEncoder.encode(password)).thenReturn("encodedPassword");
    when(userRepository.save(any(UserData.class))).thenReturn(new UserData());
    when(multiTokenService.generateSessionId()).thenReturn(sessionId);
    when(jwtService.generateToken(username, sessionId)).thenReturn(accessToken);
    when(jwtService.generateRefreshToken(username, sessionId)).thenReturn(refreshToken);

    // Act
    AuthResponse response = authService.register(request, deviceInfo);

    // Assert
    assertNotNull(response);
    assertEquals(accessToken, response.getAccessToken());
    assertEquals(refreshToken, response.getRefreshToken());
    assertEquals(sessionId, response.getSessionId());
    verify(userRepository).save(any(UserData.class));
    verify(multiTokenService).storeTokenPair(anyString(), anyString(), anyString(), anyString(), anyLong(), anyLong());
  }

  @Test
  void register_UsernameExists_ThrowsRegisterFailedException() {
    // Arrange
    RegisterRequest request = new RegisterRequest();
    request.setUsername(username);
    when(userRepository.findByUsername(username)).thenReturn(Optional.of(new UserData()));

    // Act & Assert
    assertThrows(RegisterFailedException.class, () -> authService.register(request, deviceInfo));
    verify(userRepository, never()).save(any());
  }

  @Test
  void refreshToken_ValidToken_ReturnsNewTokens() {
    // Arrange
    UserData user = new UserData();
    when(jwtService.extractUsername(refreshToken)).thenReturn(username);
    when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));
    when(jwtService.isTokenValid(refreshToken, username)).thenReturn(true);
    when(multiTokenService.canRefreshWithSession(username, sessionId, refreshToken)).thenReturn(true);
    when(jwtService.generateToken(username, sessionId)).thenReturn(accessToken);
    when(jwtService.generateRefreshToken(username, sessionId)).thenReturn(refreshToken);

    // Act
    AuthResponse response = authService.refreshToken(refreshToken, sessionId);

    // Assert
    assertNotNull(response);
    assertEquals(accessToken, response.getAccessToken());
    assertEquals(refreshToken, response.getRefreshToken());
    assertEquals(sessionId, response.getSessionId());
    verify(multiTokenService).storeTokenPair(anyString(), anyString(), anyString(), anyString(), anyLong(), anyLong());
  }

  @Test
  void refreshToken_InvalidToken_ThrowsAuthException() {
    // Arrange
    when(jwtService.extractUsername(refreshToken)).thenReturn(username);
    when(userRepository.findByUsername(username)).thenReturn(Optional.of(new UserData()));
    when(jwtService.isTokenValid(refreshToken, username)).thenReturn(false);

    // Act & Assert
    assertThrows(AuthException.class, () -> authService.refreshToken(refreshToken, sessionId));
  }

  @Test
  void logout_SpecificSession_CallsRevokeSession() {
    // Act
    authService.logout(username, sessionId);

    // Assert
    verify(multiTokenService).revokeSession(username, sessionId);
  }

  @Test
  void logoutAllSessions_CallsRevokeAllSessions() {
    // Act
    authService.logoutAllSessions(username);

    // Assert
    verify(multiTokenService).revokeAllSessions(username);
  }

  @Test
  void isAccessTokenValid_ValidToken_ReturnsTrue() {
    // Arrange
    when(jwtService.isTokenValid(accessToken, username, sessionId)).thenReturn(true);
    when(multiTokenService.validateAccessToken(username, sessionId, accessToken)).thenReturn(true);

    // Act
    boolean result = authService.isAccessTokenValid(username, sessionId, accessToken);

    // Assert
    assertTrue(result);
  }

  @Test
  void isRefreshTokenValid_ValidToken_ReturnsTrue() {
    // Arrange
    when(jwtService.isTokenValid(refreshToken, username, sessionId)).thenReturn(true);
    when(multiTokenService.validateRefreshToken(username, sessionId, refreshToken)).thenReturn(true);

    // Act
    boolean result = authService.isRefreshTokenValid(username, sessionId, refreshToken);

    // Assert
    assertTrue(result);
  }

  @Test
  void areTokensTied_ValidTokens_ReturnsTrue() {
    // Arrange
    when(jwtService.isTokenValid(accessToken, username, sessionId)).thenReturn(true);
    when(jwtService.isTokenValid(refreshToken, username, sessionId)).thenReturn(true);
    when(multiTokenService.validateTokenPair(username, sessionId, accessToken, refreshToken)).thenReturn(true);

    // Act
    boolean result = authService.areTokensTied(username, sessionId, accessToken, refreshToken);

    // Assert
    assertTrue(result);
  }
}