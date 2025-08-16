package com.frmnjn.auth.config;

import com.frmnjn.auth.dto.ErrorResponse;
import com.frmnjn.auth.exception.LoginFailedException;
import com.frmnjn.auth.exception.RegisterFailedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.time.LocalDateTime;

@ControllerAdvice
public class ControllerExceptionHandler {

  @ExceptionHandler(LoginFailedException.class)
  @ResponseStatus(HttpStatus.UNAUTHORIZED)
  public ResponseEntity<ErrorResponse> loginFailedException(LoginFailedException ex) {
    ErrorResponse errorResponse = new ErrorResponse(
        "Login Failed",
        ex.getMessage(),
        LocalDateTime.now(),
        HttpStatus.UNAUTHORIZED.value()
    );

    return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
  }

  @ExceptionHandler(RegisterFailedException.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  public ResponseEntity<ErrorResponse> registerFailedException(RegisterFailedException ex) {
    ErrorResponse errorResponse = new ErrorResponse(
        "Login Failed",
        ex.getMessage(),
        LocalDateTime.now(),
        HttpStatus.INTERNAL_SERVER_ERROR.value()
    );

    return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
  }

  // Handle generic exceptions
  @ExceptionHandler(Exception.class)
  @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
  public ResponseEntity<ErrorResponse> handleAllExceptions(Exception ex) {
    ErrorResponse errorResponse = new ErrorResponse(
        "Internal Server Error",
        ex.getMessage(),
        LocalDateTime.now(),
        HttpStatus.INTERNAL_SERVER_ERROR.value()
    );

    return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
  }
}
