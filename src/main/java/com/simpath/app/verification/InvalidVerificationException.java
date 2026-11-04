package com.simpath.app.verification;
public class InvalidVerificationException extends RuntimeException {
    public InvalidVerificationException() { super("Invalid or expired verification token."); }
}
