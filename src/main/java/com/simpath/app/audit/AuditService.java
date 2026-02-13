package com.simpath.app.audit;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
public class AuditService {
    private final AuditEventRepository repo;

    public AuditService(AuditEventRepository repo) {
        this.repo = repo;
    }

    @Transactional
    public void log(String type, UUID userId, String detail, String ip, String userAgent) {
        AuditEvent e = new AuditEvent();
        e.setType(type);
        e.setUserId(userId);
        e.setDetail(detail);
        e.setIp(ip);
        e.setUserAgent(userAgent);
        repo.save(e);
    }
}
