package com.simpath.app.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import static org.assertj.core.api.Assertions.*;

class ClientAddressResolverTest {
    @Test void untrustedClientsCannotSpoofTheirAddress() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.0.2.1"); request.addHeader("X-Forwarded-For", "198.51.100.1");
        assertThat(new ClientAddressResolver("192.0.2.2").resolve(request)).isEqualTo("192.0.2.1");
    }
    @Test void onlyExplicitTrustedProxyCanSupplySingleClientAddress() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.0.2.2"); request.addHeader("X-Forwarded-For", "198.51.100.1");
        assertThat(new ClientAddressResolver("192.0.2.2").resolve(request)).isEqualTo("198.51.100.1");
    }
    @Test void ambiguousChainsAndHostnamesAreNotAccepted() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.0.2.2"); request.addHeader("X-Forwarded-For", "198.51.100.1, 198.51.100.2");
        assertThat(new ClientAddressResolver("192.0.2.2").resolve(request)).isEqualTo("192.0.2.2");
        assertThatThrownBy(() -> new ClientAddressResolver("proxy.example.com")).isInstanceOf(IllegalArgumentException.class);
    }
}
