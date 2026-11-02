package com.simpath.app;

import com.simpath.app.auth.service.AuthService;
import com.simpath.app.auth.dto.LoginRequest;
import com.simpath.app.auth.dto.RegisterRequest;
import com.simpath.app.common.InvalidCredentialsException;
import com.simpath.app.user.entity.User;
import com.simpath.app.user.repo.UserRepository;
import com.simpath.app.security.PasswordService;
import com.simpath.app.security.RateLimitService;
import com.simpath.app.token.refresh.service.RefreshTokenService;
import com.simpath.app.token.token.JwtService;
import com.simpath.app.audit.AuditService;
import org.junit.jupiter.api.Test;
import java.util.Optional;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthLoginTest {
    private final UserRepository users = mock(UserRepository.class);
    private final PasswordService passwords = mock(PasswordService.class);
    private final RateLimitService limits = mock(RateLimitService.class);
    private final AuthService auth = new AuthService(users, passwords, mock(JwtService.class),
            mock(RefreshTokenService.class), mock(AuditService.class), limits);
    @Test void unknownUserStillPerformsPasswordComparison() {
        when(users.findByEmailIgnoreCase("absent@example.com")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> auth.login(new LoginRequest("absent@example.com", "wrong"), "test", "ip"))
                .isInstanceOf(InvalidCredentialsException.class);
        verify(passwords).matches("wrong", null);
        verify(limits).enforceLoginAccount("absent@example.com");
    }
    @Test void disabledUserStillPerformsPasswordComparison() {
        User user = new User(); user.setEnabled(false); user.setPasswordHash("stored");
        when(users.findByEmailIgnoreCase("disabled@example.com")).thenReturn(Optional.of(user));
        assertThatThrownBy(() -> auth.login(new LoginRequest("disabled@example.com", "wrong"), "test", "ip"))
                .isInstanceOf(InvalidCredentialsException.class);
        verify(passwords).matches("wrong", "stored");
    }
    @Test void duplicateRegistrationStillHashesAndUsesAtomicInsert() {
        when(passwords.hash("correct horse battery staple")).thenReturn("hash");
        auth.register(new RegisterRequest("EXISTING@example.com", "correct horse battery staple"));
        verify(passwords).hash("correct horse battery staple");
        verify(users).insertIfAbsent(any(), eq("existing@example.com"), eq("hash"), any());
    }
}
