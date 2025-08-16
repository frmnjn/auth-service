package com.frmnjn.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.Map;

@Data
public class AuthResponse {

  @JsonProperty("access_token")
  private String accessToken;

  @JsonProperty("refresh_token")
  private String refreshToken;

  @JsonProperty("session_id")
  private String sessionId; // CRITICAL: Client must store and use this

  @JsonProperty("token_type")
  private String tokenType = "Bearer";

  @JsonProperty("expires_in")
  private Long expiresIn = 900L; // 15 minutes for access token

  // Optional: Include device/session info for client reference
  @JsonProperty("device_info")
  private Map<String, String> deviceInfo;

  // Optional: Timestamp when tokens were issued
  @JsonProperty("issued_at")
  private Long issuedAt = System.currentTimeMillis() / 1000;
}