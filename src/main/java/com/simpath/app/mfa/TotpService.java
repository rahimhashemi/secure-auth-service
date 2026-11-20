package com.simpath.app.mfa;

import org.springframework.stereotype.Component;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;

@Component
public class TotpService {
    private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final int PERIOD_SECONDS = 30;
    private final SecureRandom random = new SecureRandom();

    public String generateSecret() {
        byte[] seed = new byte[20];
        random.nextBytes(seed);
        StringBuilder result = new StringBuilder(32);
        int buffer = 0;
        int bits = 0;
        for (byte b : seed) {
            buffer = (buffer << 8) | (b & 255);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                result.append(BASE32[(buffer >>> bits) & 31]);
            }
        }
        if (bits != 0) result.append(BASE32[(buffer << (5 - bits)) & 31]);
        return result.toString();
    }

    public String provisioningUri(String email, String secret) {
        String issuer = "Secure Auth Service";
        return "otpauth://totp/" + encode(issuer + ":" + email) + "?secret=" + secret
                + "&issuer=" + encode(issuer) + "&algorithm=SHA1&digits=6&period=30";
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    // Returns the accepted moving counter, or -1. Never accept the same counter twice.
    public long verify(String secret, String code, Instant now, long lastUsedCounter) {
        if (code == null || !code.matches("[0-9]{6}")) return -1L;
        long current = Math.floorDiv(now.getEpochSecond(), PERIOD_SECONDS);
        byte[] key = decode(secret);
        for (long counter = current - 1; counter <= current + 1; counter++) {
            if (counter < 0 || counter <= lastUsedCounter) continue;
            byte[] expected = codeFor(key, counter).getBytes(StandardCharsets.US_ASCII);
            if (MessageDigest.isEqual(expected, code.getBytes(StandardCharsets.US_ASCII))) return counter;
        }
        return -1L;
    }

    public String codeAt(String secret, Instant time) {
        return codeFor(decode(secret), Math.floorDiv(time.getEpochSecond(), PERIOD_SECONDS));
    }

    private String codeFor(byte[] key, long counter) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array());
            int offset = hash[hash.length - 1] & 15;
            int binary = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16)
                    | ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255);
            return String.format(java.util.Locale.ROOT, "%06d", binary % 1_000_000);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("TOTP unavailable.", ex);
        }
    }

    private byte[] decode(String base32) {
        if (base32 == null || base32.isEmpty()) throw new IllegalArgumentException("Invalid TOTP secret");
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (int i = 0; i < base32.length(); i++) {
            int value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(base32.charAt(i));
            if (value < 0) throw new IllegalArgumentException("Invalid TOTP secret");
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                output.write((buffer >>> bits) & 255);
            }
        }
        return output.toByteArray();
    }
}
