package com.frmnjn.auth.dto;

import lombok.Data;

@Data
public class SessionIdentifier {
  private String username;
  private String sessionId;
}
