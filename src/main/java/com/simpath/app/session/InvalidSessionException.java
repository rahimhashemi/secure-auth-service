package com.simpath.app.session;

public class InvalidSessionException extends RuntimeException {
    public InvalidSessionException() { super("Invalid session."); }
}
