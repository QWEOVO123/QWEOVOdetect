package org.detector.qweovodetect.stats.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "sni_logs", indexes = {
        @Index(name = "idx_sni_host", columnList = "sniHost"),
        @Index(name = "idx_sni_protocol", columnList = "protocol"),
        @Index(name = "idx_sni_listen_port", columnList = "listenPort"),
        @Index(name = "idx_sni_time", columnList = "detectTime")
})
public class SniLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String clientIp;

    @Column(nullable = false, columnDefinition = "integer default 0")
    private int listenPort;

    @Column(nullable = false)
    private String sniHost;

    @Column(nullable = false, length = 16, columnDefinition = "varchar(16) default 'TLS'")
    private String protocol = "TLS";

    @Column(nullable = false)
    private LocalDateTime detectTime;

    public SniLog() {}

    public SniLog(String clientIp, String sniHost) {
        this(clientIp, 0, sniHost, "TLS");
    }

    public SniLog(String clientIp, int listenPort, String sniHost) {
        this(clientIp, listenPort, sniHost, "TLS");
    }

    public SniLog(String clientIp, int listenPort, String sniHost, String protocol) {
        this.clientIp = clientIp;
        this.listenPort = listenPort;
        this.sniHost = sniHost;
        this.protocol = protocol == null || protocol.isBlank() ? "TLS" : protocol;
        this.detectTime = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getClientIp() { return clientIp; }
    public void setClientIp(String clientIp) { this.clientIp = clientIp; }
    public int getListenPort() { return listenPort; }
    public void setListenPort(int listenPort) { this.listenPort = listenPort; }
    public String getSniHost() { return sniHost; }
    public void setSniHost(String sniHost) { this.sniHost = sniHost; }
    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }
    public LocalDateTime getDetectTime() { return detectTime; }
    public void setDetectTime(LocalDateTime detectTime) { this.detectTime = detectTime; }
}
