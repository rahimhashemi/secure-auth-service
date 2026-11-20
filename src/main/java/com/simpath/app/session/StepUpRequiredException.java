package com.simpath.app.session;

public class StepUpRequiredException extends RuntimeException {
    public StepUpRequiredException() {
        super("Recent authentication is required.");
    }
}
