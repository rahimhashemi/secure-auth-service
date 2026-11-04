package com.simpath.app;
import com.simpath.app.verification.OutboxCipher;
import org.junit.jupiter.api.Test;
import java.util.UUID;
import static org.assertj.core.api.Assertions.*;
class OutboxCipherTest {
    private final OutboxCipher cipher = new OutboxCipher("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    @Test void encryptionIsRandomizedAndBoundToTheOutboxId() {
        UUID id = UUID.randomUUID(); String first = cipher.encrypt(id, "private token");
        assertThat(cipher.decrypt(id, first)).isEqualTo("private token");
        assertThat(cipher.encrypt(id, "private token")).isNotEqualTo(first);
        assertThatThrownBy(() -> cipher.decrypt(UUID.randomUUID(), first)).isInstanceOf(IllegalStateException.class);
        byte[] bytes = java.util.Base64.getDecoder().decode(first); bytes[bytes.length - 1] ^= 1;
        assertThatThrownBy(() -> cipher.decrypt(id, java.util.Base64.getEncoder().encodeToString(bytes))).isInstanceOf(IllegalStateException.class);
    }
    @Test void invalidKeysAreRejected() {
        assertThatThrownBy(() -> new OutboxCipher("short")).isInstanceOf(IllegalArgumentException.class);
    }
}
