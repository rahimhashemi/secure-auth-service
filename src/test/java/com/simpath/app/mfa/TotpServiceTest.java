package com.simpath.app.mfa;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;

class TotpServiceTest {
    private final TotpService totp = new TotpService();
    // RFC 6238 SHA-1 seed: "12345678901234567890" encoded as base32.
    private final String seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    @Test void followsRfc6238SixDigitVectors() {
        assertThat(totp.codeAt(seed, Instant.ofEpochSecond(59))).isEqualTo("287082");
        assertThat(totp.codeAt(seed, Instant.ofEpochSecond(1111111109))).isEqualTo("081804");
        assertThat(totp.codeAt(seed, Instant.ofEpochSecond(1111111111))).isEqualTo("050471");
        assertThat(totp.codeAt(seed, Instant.ofEpochSecond(1234567890))).isEqualTo("005924");
    }

    @Test void allowsOneClockStepOfDriftButRejectsReplay() {
        Instant time = Instant.ofEpochSecond(1000);
        String code = totp.codeAt(seed, time);
        long accepted = totp.verify(seed, code, time, -1);
        assertThat(accepted).isEqualTo(33);
        assertThat(totp.verify(seed, code, time, accepted)).isEqualTo(-1);
        assertThat(totp.verify(seed, code, time.plusSeconds(30), -1)).isEqualTo(33);
        assertThat(totp.verify(seed, code, time.plusSeconds(90), -1)).isEqualTo(-1);
        assertThat(totp.verify(seed, "12345a", time, -1)).isEqualTo(-1);
    }

    @Test void generatesValidDistinctSecretsAndProvisioningUri() {
        String first = totp.generateSecret();
        String second = totp.generateSecret();
        assertThat(first).matches("[A-Z2-7]{32}").isNotEqualTo(second);
        assertThat(totp.provisioningUri("person@example.com", first))
                .startsWith("otpauth://totp/")
                .contains("secret=" + first, "digits=6", "period=30", "issuer=Secure+Auth+Service");
    }

    @Test void encryptionIsUserBoundAndAuthenticated() {
        MfaCipher cipher = new MfaCipher("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        UUID owner = UUID.randomUUID();
        String ciphertext = cipher.encrypt(owner, seed);
        assertThat(cipher.decrypt(owner, ciphertext)).isEqualTo(seed);
        assertThat(ciphertext).doesNotContain(seed);
        assertThat(cipher.encrypt(owner, seed)).isNotEqualTo(ciphertext);
        assertThatThrownBy(() -> cipher.decrypt(UUID.randomUUID(), ciphertext))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new MfaCipher("invalid"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
