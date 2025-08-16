package com.frmnjn.auth.dto;

import java.time.LocalDateTime;

public record ErrorResponse(
    String message,
    String details,
    LocalDateTime timestamp,
    int status
) {
}
