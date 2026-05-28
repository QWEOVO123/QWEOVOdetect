package org.detector.qweovodetect.stats.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "trojan_logs", indexes = {
        @Index(name = "idx_trojan_client_ip", columnList = "clientIp"),
        @Index(name = "idx_trojan_listen_port", columnList = "listenPort"),
        @Index(name = "idx_trojan_target_ip", columnList = "targetIp"),
        @Index(name = "idx_trojan_time", columnList = "detectTime")
})
public class TrojanLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String clientIp;

    @Column(nullable = false, columnDefinition = "integer default 0")
    private int listenPort;

    @Column(nullable = false)
    private String targetIp;

    @Column(nullable = false)
    private int uploadBytes;

    @Column(nullable = false)
    private int downloadBytes;

    @Column(nullable = false)
    private LocalDateTime detectTime;

    public TrojanLog() {
    }

    public TrojanLog(String clientIp, String targetIp, int uploadBytes, int downloadBytes) {
        this(clientIp, 0, targetIp, uploadBytes, downloadBytes);
    }

    public TrojanLog(String clientIp, int listenPort, String targetIp, int uploadBytes, int downloadBytes) {
        this.clientIp = clientIp;
        this.listenPort = listenPort;
        this.targetIp = targetIp;
        this.uploadBytes = uploadBytes;
        this.downloadBytes = downloadBytes;
        this.detectTime = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getClientIp() {
        return clientIp;
    }

    public void setClientIp(String clientIp) {
        this.clientIp = clientIp;
    }

    public int getListenPort() {
        return listenPort;
    }

    public void setListenPort(int listenPort) {
        this.listenPort = listenPort;
    }

    public String getTargetIp() {
        return targetIp;
    }

    public void setTargetIp(String targetIp) {
        this.targetIp = targetIp;
    }

    public int getUploadBytes() {
        return uploadBytes;
    }

    public void setUploadBytes(int uploadBytes) {
        this.uploadBytes = uploadBytes;
    }

    public int getDownloadBytes() {
        return downloadBytes;
    }

    public void setDownloadBytes(int downloadBytes) {
        this.downloadBytes = downloadBytes;
    }

    public LocalDateTime getDetectTime() {
        return detectTime;
    }

    public void setDetectTime(LocalDateTime detectTime) {
        this.detectTime = detectTime;
    }
}
