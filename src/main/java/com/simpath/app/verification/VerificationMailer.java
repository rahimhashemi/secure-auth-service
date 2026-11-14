package com.simpath.app.verification;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;
import java.net.URI;
@Component
public class VerificationMailer {
    private final JavaMailSender mail;
    private final String url;
    private final String from;
    private final URI resetUrl;
    public VerificationMailer(JavaMailSender mail, @Value("${app.verification.public-url}") String url,
            @Value("${app.verification.from}") String from) {
        URI uri = URI.create(url);
        boolean local = "localhost".equalsIgnoreCase(uri.getHost()) || "127.0.0.1".equals(uri.getHost()) || "[::1]".equals(uri.getHost());
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                || !("https".equals(uri.getScheme()) || (local && "http".equals(uri.getScheme())))) {
            throw new IllegalArgumentException("Verification URL must use HTTPS (HTTP is allowed on loopback only)");
        }
        this.mail = mail; this.url = url; this.from = from;
        this.resetUrl = uri.resolve("reset-password.html");
    }
    public void send(String recipient, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from); message.setTo(recipient); message.setSubject("Verify your email - Secure Auth Service");
        message.setText("Confirm your email using this link within 30 minutes:\n" + url + "#token=" + token
                + "\nIf you did not request this, ignore this email. Never verify an account you did not create.");
        mail.send(message);
    }

    public void sendPasswordReset(String recipient, String token) {
        sendMessage(recipient, "Reset your password - Secure Auth Service",
                "Reset your password within 15 minutes:\n" + resetUrl + "#token=" + token
                        + "\nIf you did not request this, you can ignore this email.");
    }

    public void sendPasswordChanged(String recipient) {
        sendMessage(recipient, "Your password was reset - Secure Auth Service",
                "Your password was reset and your existing sessions were signed out."
                        + " If you did not make this change, contact support.");
    }

    private void sendMessage(String recipient, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(recipient);
        message.setSubject(subject);
        message.setText(body);
        mail.send(message);
    }
}
