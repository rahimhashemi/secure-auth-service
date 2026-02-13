package com.simpath.app.common;

public class InvalidRefreshTokenException extends RuntimeException {
  public InvalidRefreshTokenException(String msg) { super(msg); }
}
