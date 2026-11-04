package com.simpath.app.verification;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
@Component
public class MailOutboxWorker {
    private final MailOutboxDelivery delivery;
    private final boolean enabled;
    public MailOutboxWorker(MailOutboxDelivery delivery, @Value("${app.verification.worker-enabled:true}") boolean enabled) {
        this.delivery = delivery; this.enabled = enabled;
    }
    @Scheduled(fixedDelayString = "${app.verification.poll-millis:10000}")
    public void poll() {
        if (!enabled) return;
        delivery.scrub();
        for (int i = 0; i < 5; i++) if (!delivery.deliverOne()) return;
    }
}
