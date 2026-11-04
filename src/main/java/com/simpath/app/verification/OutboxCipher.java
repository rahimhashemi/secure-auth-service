package com.simpath.app.verification;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
@Component
public class OutboxCipher {
    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();
    public OutboxCipher(@Value("${app.verification.outbox-key}") String hex) {
        if (hex == null || !hex.matches("[0-9a-fA-F]{64}")) throw new IllegalArgumentException("Outbox key must contain 64 hex characters");
        key = new SecretKeySpec(HexFormat.of().parseHex(hex), "AES");
    }
    public String encrypt(UUID id, String plain) {
        try {
            byte[] nonce = new byte[12]; random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            cipher.updateAAD(id.toString().getBytes(StandardCharsets.UTF_8));
            byte[] body = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ByteBuffer.allocate(nonce.length + body.length).put(nonce).put(body).array());
        } catch (java.security.GeneralSecurityException ex) { throw new IllegalStateException("Cannot encrypt outbox payload", ex); }
    }
    public String decrypt(UUID id, String encoded) {
        try {
            byte[] bytes = Base64.getDecoder().decode(encoded);
            if (bytes.length < 28) throw new IllegalArgumentException("Invalid encrypted payload");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, bytes, 0, 12));
            cipher.updateAAD(id.toString().getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(bytes, 12, bytes.length - 12), StandardCharsets.UTF_8);
        } catch (java.security.GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Cannot decrypt outbox payload");
        }
    }
}
