package com.simpath.app.session;

public class InvalidStepUpException extends RuntimeException {
    public InvalidStepUpException() {
        super("Invalid reauthentication credentials.");
    }
}
