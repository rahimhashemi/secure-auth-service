package com.simpath.app;

import com.simpath.app.token.token.JwtAuthFilter;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.assertj.core.api.Assertions.*;

class JwtAuthFilterTest {
    private final com.simpath.app.session.SessionService sessions = org.mockito.Mockito.mock(com.simpath.app.session.SessionService.class);
    private final JwtAuthFilter filter = new JwtAuthFilter(io.jsonwebtoken.security.Keys.hmacShaKeyFor("test-only-key-with-at-least-thirty-two-characters".getBytes(java.nio.charset.StandardCharsets.UTF_8)), "test", new com.simpath.app.common.ApiErrorWriter(tools.jackson.databind.json.JsonMapper.builder().findAndAddModules().build()), sessions);
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
    @Test void sessionStoreFailureReturns503AndDoesNotReachEndpoint() throws Exception {
        javax.crypto.SecretKey key = io.jsonwebtoken.security.Keys.hmacShaKeyFor("test-only-key-with-at-least-thirty-two-characters".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String token = io.jsonwebtoken.Jwts.builder().setIssuer("test").setSubject(java.util.UUID.randomUUID().toString())
                .claim("sid", java.util.UUID.randomUUID().toString())
                .setExpiration(java.util.Date.from(java.time.Instant.now().plusSeconds(60))).signWith(key).compact();
        org.mockito.Mockito.when(sessions.authorize(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
                .thenThrow(new org.springframework.dao.DataAccessResourceFailureException("down"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/me");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> { throw new AssertionError("Endpoint invoked"); });
        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getContentAsString()).contains("SESSION_STORE_UNAVAILABLE");
        assertThat(response.getHeader("Retry-After")).isEqualTo("1");
    }

}


