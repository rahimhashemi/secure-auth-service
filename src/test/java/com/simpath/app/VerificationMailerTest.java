package com.simpath.app;
import com.simpath.app.verification.VerificationMailer;
import org.junit.jupiter.api.Test;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.mockito.ArgumentCaptor;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;
class VerificationMailerTest {
    @Test void mailUsesConfiguredOriginAndFragmentToken() {
        JavaMailSender sender = mock(JavaMailSender.class);
        new VerificationMailer(sender, "https://auth.example.com/verify-email.html", "no-reply@example.com").send("user@example.com", "opaque-token");
        ArgumentCaptor<SimpleMailMessage> sent = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(sender).send(sent.capture());
        assertThat(sent.getValue().getTo()).containsExactly("user@example.com");
        assertThat(sent.getValue().getText()).contains("https://auth.example.com/verify-email.html#token=opaque-token");
    }
    @Test void insecureRemoteOrAmbiguousOriginsAreRejected() {
        for (String url : java.util.List.of("http://remote.example/verify", "https://user@remote.example/verify", "https://remote.example/verify?redirect=other", "https://remote.example/verify#x")) {
            assertThatThrownBy(() -> new VerificationMailer(mock(JavaMailSender.class), url, "no-reply@example.com"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
