package com.simpath.app.security;
import java.util.Locale;
public final class EmailNormalizer {
    private EmailNormalizer() { }
    public static String normalize(String email) { return email.trim().toLowerCase(Locale.ROOT); }
}
