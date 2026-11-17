package com.simpath.app.passwordreset;

public class InvalidPasswordResetException extends RuntimeException {
    public InvalidPasswordResetException() {
        super("Invalid or expired password reset token.");
    }
}
