package com.simpath.app;

import com.simpath.app.token.token.JwtAuthFilter;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.assertj.core.api.Assertions.*;

class JwtAuthFilterTest {
    private final JwtAuthFilter filter = new JwtAuthFilter(io.jsonwebtoken.security.Keys.hmacShaKeyFor("test-only-key-with-at-least-thirty-two-characters".getBytes(java.nio.charset.StandardCharsets.UTF_8)), "test");
    @Test void downstreamFailureIsNotRewrittenAsInvalidToken() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertThatThrownBy(() -> filter.doFilter(new MockHttpServletRequest(), response,
            (request, result) -> { throw new ServletException("downstream failure"); }))
            .isInstanceOf(ServletException.class).hasMessage("downstream failure");
        assertThat(response.getStatus()).isEqualTo(200);
    }
    @Test void invalidTokenReturns401WithoutInvokingEndpoint() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer invalid");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> { throw new AssertionError("Endpoint invoked"); });
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test void staleBearerDoesNotPreventLogin() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/login");
        request.addHeader("Authorization", "Bearer invalid");
        MockHttpServletResponse response = new MockHttpServletResponse();
        java.util.concurrent.atomic.AtomicBoolean called = new java.util.concurrent.atomic.AtomicBoolean();
        filter.doFilter(request, response, (req, res) -> called.set(true));
        assertThat(called.get()).isTrue();
        assertThat(response.getStatus()).isEqualTo(200);
    }
}

