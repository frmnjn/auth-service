package com.frmnjn.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenRequest {
  private String refreshToken;
  private String sessionId; // CRITICAL: Client must send this
}
