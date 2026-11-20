package com.simpath.app.mfa;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Component
public class MfaCipher {
    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    public MfaCipher(@Value("${app.mfa.encryption-key}") String hex) {
        if (hex == null || !hex.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("MFA encryption key must be 64 hex characters.");
        }
        this.key = new SecretKeySpec(HexFormat.of().parseHex(hex), "AES");
    }

    public String encrypt(UUID userId, String secret) {
        try {
            byte[] nonce = new byte[12];
            random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            cipher.updateAAD(userId.toString().getBytes(StandardCharsets.UTF_8));
            byte[] body = cipher.doFinal(secret.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ByteBuffer.allocate(nonce.length + body.length)
                    .put(nonce).put(body).array());
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Could not encrypt MFA secret.", ex);
        }
    }

    public String decrypt(UUID userId, String encrypted) {
        try {
            byte[] payload = Base64.getDecoder().decode(encrypted);
            if (payload.length < 28) throw new IllegalArgumentException("Invalid ciphertext");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, payload, 0, 12));
            cipher.updateAAD(userId.toString().getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(payload, 12, payload.length - 12), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalStateException("Could not decrypt MFA secret.");
        }
    }
}
