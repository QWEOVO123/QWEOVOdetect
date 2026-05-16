package org.detector.qweovodetect.stats.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "ss_logs", indexes = {
        @Index(name = "idx_ss_client_ip", columnList = "clientIp"),
        @Index(name = "idx_ss_target_ip", columnList = "targetIp"),
        @Index(name = "idx_ss_time", columnList = "detectTime")
})
public class SsLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String clientIp;

    @Column(nullable = false)
    private String targetIp;

    @Column(nullable = false)
    private LocalDateTime detectTime;

    public SsLog() {}

    public SsLog(String clientIp, String targetIp) {
        this.clientIp = clientIp;
        this.targetIp = targetIp;
        this.detectTime = LocalDateTime.now();
    }

    // getter/setter
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getClientIp() { return clientIp; }
    public void setClientIp(String clientIp) { this.clientIp = clientIp; }
    public String getTargetIp() { return targetIp; }
    public void setTargetIp(String targetIp) { this.targetIp = targetIp; }
    public LocalDateTime getDetectTime() { return detectTime; }
    public void setDetectTime(LocalDateTime detectTime) { this.detectTime = detectTime; }
}