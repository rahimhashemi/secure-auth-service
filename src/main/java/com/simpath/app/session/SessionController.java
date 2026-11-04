package com.simpath.app.session;

import com.simpath.app.audit.AuditService;
import com.simpath.app.security.ClientAddressResolver;
import com.simpath.app.token.token.AuthPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/sessions")
public class SessionController {
    private final SessionService sessions;
    private final AuditService audit;
    private final ClientAddressResolver addresses;

    public SessionController(SessionService sessions, AuditService audit, ClientAddressResolver addresses) {
        this.sessions = sessions;
        this.audit = audit;
        this.addresses = addresses;
    }

    @GetMapping
    public List<SessionResponse> list(@AuthenticationPrincipal AuthPrincipal principal,
            @RequestParam(defaultValue = "0") @Min(0) @Max(10000) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        return sessions.list(UUID.fromString(principal.userId()), UUID.fromString(principal.sessionId()), page, size);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void revoke(@AuthenticationPrincipal AuthPrincipal principal, @PathVariable UUID id, HttpServletRequest request) {
        UUID userId = UUID.fromString(principal.userId());
        sessions.revokeManaged(userId, UUID.fromString(principal.sessionId()), id);
        audit.log("SESSION_REVOKE", userId, "sessionId=" + id, addresses.resolve(request), request.getHeader("User-Agent"));
    }

    @DeleteMapping("/others")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void revokeOthers(@AuthenticationPrincipal AuthPrincipal principal, HttpServletRequest request) {
        UUID userId = UUID.fromString(principal.userId());
        sessions.revokeOtherSessions(userId, UUID.fromString(principal.sessionId()));
        audit.log("SESSION_REVOKE_OTHERS", userId, "keep=" + principal.sessionId(), addresses.resolve(request), request.getHeader("User-Agent"));
    }
}
