package com.frmnjn.auth.controller;

import com.frmnjn.auth.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class BaseController {

  private final JwtService jwtService;

  @GetMapping("/api/validate")
  public ResponseEntity<Void> validate(HttpServletRequest request) {
    String authHeader = request.getHeader("Authorization");
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return ResponseEntity.status(401).build();
    }

    String token = authHeader.substring(7);
    Date expiration = jwtService.extractExpiration(token);
    long now = System.currentTimeMillis();
    long maxAgeSeconds = (expiration.getTime() - now) / 1000;

    if (maxAgeSeconds <= 0) {
      return ResponseEntity.status(401).build();
    }

    return ResponseEntity.ok()
        .header("Cache-Control", "max-age=" + maxAgeSeconds)
        .build();
  }
}
