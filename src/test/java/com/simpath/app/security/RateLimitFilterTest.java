package com.simpath.app.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class RateLimitFilterTest {
    private final RateLimitService service = mock(RateLimitService.class);
    private final RateLimitFilter filter = new RateLimitFilter(service, new ClientAddressResolver(""));

    @Test void rejectedLoginReturns429AndRetryAfterWithoutCallingEndpoint() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/login");
        request.setRemoteAddr("192.0.2.1");
        when(service.check("login", "192.0.2.1")).thenReturn(12L);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);
        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeader("Retry-After")).isEqualTo("12");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getContentAsString()).contains("RATE_LIMIT_EXCEEDED");
        verifyNoInteractions(chain);
    }

    @Test void forwardedHeadersCannotSelectAnotherBucket() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/refresh");
        request.setRemoteAddr("192.0.2.2");
        request.addHeader("X-Forwarded-For", "198.51.100.10");
        request.addHeader("Forwarded", "for=198.51.100.20");
        filter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));
        verify(service).check("refresh", "192.0.2.2");
        verifyNoMoreInteractions(service);
    }

    @Test void redisFailureReturns503InsteadOfAllowingAuthentication() throws Exception {
        when(service.check(anyString(), anyString())).thenThrow(new DataAccessResourceFailureException("down"));
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("POST", "/auth/login"), response, chain);
        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getContentAsString()).contains("RATE_LIMIT_UNAVAILABLE");
        verifyNoInteractions(chain);
    }

    @Test void unrelatedPathsAndMethodsDoNotUseRedis() throws Exception {
        filter.doFilter(new MockHttpServletRequest("GET", "/auth/login"), new MockHttpServletResponse(), mock(FilterChain.class));
        filter.doFilter(new MockHttpServletRequest("POST", "/auth/logout"), new MockHttpServletResponse(), mock(FilterChain.class));
        filter.doFilter(new MockHttpServletRequest("GET", "/me"), new MockHttpServletResponse(), mock(FilterChain.class));
        verifyNoInteractions(service);
    }

    @Test void contextPathIsSupportedAndAllowedRequestReachesEndpoint() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/bank/auth/login");
        request.setContextPath("/bank");
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        verify(service).check("login", request.getRemoteAddr());
        verify(chain).doFilter(any(), any());
    }

    @Test void downstreamFailuresAreNotReportedAsRedisOutages() {
        FilterChain chain = (request, response) -> { throw new ServletException("endpoint error"); };
        assertThatThrownBy(() -> filter.doFilter(new MockHttpServletRequest("POST", "/auth/login"),
                new MockHttpServletResponse(), chain)).isInstanceOf(ServletException.class);
    }
}

