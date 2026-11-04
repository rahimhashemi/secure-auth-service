package com.simpath.app.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

// Use the same default PathPattern semantics as MVC; never decode an entire URL by hand.
public final class AuthEndpointMatcher {
    private static final PathPatternRequestMatcher REGISTER = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, "/auth/register");
    private static final PathPatternRequestMatcher LOGIN = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, "/auth/login");
    private static final PathPatternRequestMatcher REFRESH = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, "/auth/refresh");
    private static final PathPatternRequestMatcher VERIFY_REQUEST = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, "/auth/email-verification/request");
    private static final PathPatternRequestMatcher VERIFY_CONFIRM = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, "/auth/email-verification/confirm");
    private AuthEndpointMatcher() { }
    public static String operation(HttpServletRequest request) {
        if (REGISTER.matches(request)) return "register";
        if (LOGIN.matches(request)) return "login";
        if (REFRESH.matches(request)) return "refresh";
        if (VERIFY_REQUEST.matches(request)) return "verification-request";
        if (VERIFY_CONFIRM.matches(request)) return "verification-confirm";
        return null;
    }
}
