package com.simpath.app;

import com.simpath.app.common.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import static org.assertj.core.api.Assertions.*;

class ExceptionResponseTest {
    @Test void internalIllegalArgumentIsNotExposedAsClientError() {
        org.springframework.http.ResponseEntity<ApiError> response = new GlobalExceptionHandler()
                .fallback(new IllegalArgumentException("internal-secret-detail"), new MockHttpServletRequest());
        assertThat(response.getStatusCode().value()).isEqualTo(500);
        assertThat(response.getBody().message()).doesNotContain("internal-secret-detail");
        assertThat(response.getHeaders().getFirst("X-Error-Id")).isNotBlank();
    }
    @Test void credentialsHaveStableUnauthorizedResponse() {
        org.springframework.http.ResponseEntity<ApiError> response = new GlobalExceptionHandler()
                .credentials(new InvalidCredentialsException(), new MockHttpServletRequest());
        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody().code()).isEqualTo("INVALID_CREDENTIALS");
    }
}
