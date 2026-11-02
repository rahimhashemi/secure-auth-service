package com.simpath.app.security;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class PasswordPolicyTest {
    private final RegistrationPasswordValidator policy = new RegistrationPasswordValidator();
    @Test void weakPasswordsAreRejectedAndPassphrasesAccepted() {
        assertThat(policy.isValid("a", null)).isFalse();
        assertThat(policy.isValid(" ".repeat(12), null)).isFalse();
        assertThat(policy.isValid("correct horse battery staple", null)).isTrue();
    }
    @Test void bcryptLimitIsMeasuredInUtf8Bytes() {
        assertThat(policy.isValid("a".repeat(72), null)).isTrue();
        assertThat(policy.isValid("a".repeat(73), null)).isFalse();
        assertThat(policy.isValid("ش".repeat(36), null)).isTrue();
        assertThat(policy.isValid("ش".repeat(37), null)).isFalse();
    }
    @Test void missingUserAndOversizeInputNeverAuthenticate() {
        PasswordService passwords = new PasswordService();
        String hash = passwords.hash("correct horse battery staple");
        assertThat(passwords.matches("correct horse battery staple", hash)).isTrue();
        assertThat(passwords.matches("correct horse battery staple", null)).isFalse();
        assertThat(passwords.matches("a".repeat(73), hash)).isFalse();
    }
}
