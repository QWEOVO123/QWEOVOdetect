package org.detector.qweovodetect.stats.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "risk_targets", indexes = {
        @Index(name = "idx_risk_protocol", columnList = "protocol"),
        @Index(name = "idx_risk_target_ip", columnList = "targetIp"),
        @Index(name = "idx_risk_last_seen", columnList = "lastSeenTime")
}, uniqueConstraints = {
        @UniqueConstraint(name = "uk_risk_protocol_target", columnNames = {"protocol", "targetIp"})
})
public class RiskTarget {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 32)
    private String protocol;

    @Column(nullable = false)
    private String targetIp;

    @Column(nullable = false)
    private long triggerCount;

    @Column(nullable = false)
    private String riskLevel;

    @Column(nullable = false)
    private LocalDateTime firstSeenTime;

    @Column(nullable = false)
    private LocalDateTime lastSeenTime;

    public RiskTarget() {
    }

    public RiskTarget(String protocol, String targetIp, long triggerCount, String riskLevel) {
        LocalDateTime now = LocalDateTime.now();
        this.protocol = protocol;
        this.targetIp = targetIp;
        this.triggerCount = triggerCount;
        this.riskLevel = riskLevel;
        this.firstSeenTime = now;
        this.lastSeenTime = now;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getTargetIp() {
        return targetIp;
    }

    public void setTargetIp(String targetIp) {
        this.targetIp = targetIp;
    }

    public long getTriggerCount() {
        return triggerCount;
    }

    public void setTriggerCount(long triggerCount) {
        this.triggerCount = triggerCount;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public LocalDateTime getFirstSeenTime() {
        return firstSeenTime;
    }

    public void setFirstSeenTime(LocalDateTime firstSeenTime) {
        this.firstSeenTime = firstSeenTime;
    }

    public LocalDateTime getLastSeenTime() {
        return lastSeenTime;
    }

    public void setLastSeenTime(LocalDateTime lastSeenTime) {
        this.lastSeenTime = lastSeenTime;
    }
}
