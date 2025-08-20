package com.frmnjn.auth.config;

import com.frmnjn.auth.service.JwtService;
import com.frmnjn.auth.service.MultiTokenService;
import com.frmnjn.auth.service.UserInfoService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

  private final JwtService jwtService;
  private final UserInfoService userInfoService;
  private final MultiTokenService multiTokenService;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain
  ) throws ServletException, IOException {

    final String authHeader = request.getHeader("Authorization");
    final String jwt;
    final String username;
    final String sessionId;

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }

    jwt = authHeader.substring(7);

    try {
      username = jwtService.extractUsername(jwt);
      sessionId = jwtService.extractSessionId(jwt); // Extract session ID from JWT

      if (username != null && sessionId != null && SecurityContextHolder.getContext().getAuthentication() == null) {

        // Validate JWT token signature, expiration, and session ID
        if (!jwtService.isTokenValid(jwt, username, sessionId)) {
          log.info("JWT token is invalid, expired, or session ID mismatch for user: {}", username);
          response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          return;
        }

        // Validate token exists in Redis with session ID (not revoked)
        if (!multiTokenService.validateAccessToken(username, sessionId, jwt)) {
          log.info("Access token not found in Redis or revoked for user: {} session: {}", username, sessionId);
          response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          return;
        }

        UserDetails userDetails = userInfoService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities()
        );
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);

        log.info("Successfully authenticated user: {} with session: {}", username, sessionId);
      }
    } catch (Exception e) {
      log.error("Error during JWT authentication", e);
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      return;
    }

    filterChain.doFilter(request, response);
  }
}