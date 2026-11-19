package com.simpath.app.mfa;

public class InvalidMfaException extends RuntimeException {
    public InvalidMfaException() {
        super("Invalid or expired MFA credentials.");
    }
}
