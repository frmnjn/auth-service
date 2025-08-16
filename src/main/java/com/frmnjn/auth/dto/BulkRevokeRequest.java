package com.frmnjn.auth.dto;

import lombok.Data;

import java.util.List;

@Data
public class BulkRevokeRequest {
  private List<SessionIdentifier> sessions;
}
