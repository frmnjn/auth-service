package com.frmnjn.auth.controller;

import com.frmnjn.auth.dto.AuthResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class BaseController {

  @GetMapping("/api/validate")
  public ResponseEntity<AuthResponse> validate() {
    return ResponseEntity.ok().build();
  }
}
