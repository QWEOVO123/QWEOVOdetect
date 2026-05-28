package org.detector.qweovodetect.stats.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "block_rules", indexes = {
        @Index(name = "idx_block_keyword", columnList = "keyword"),
        @Index(name = "idx_block_enabled", columnList = "enabled")
})
public class BlockRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 128)
    private String keyword;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false)
    private LocalDateTime createTime = LocalDateTime.now();

    public BlockRule() {
    }

    public BlockRule(String keyword) {
        this.keyword = keyword;
        this.enabled = true;
        this.createTime = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public String getKeyword() {
        return keyword;
    }

    public void setKeyword(String keyword) {
        this.keyword = keyword;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public LocalDateTime getCreateTime() {
        return createTime;
    }

    public void setCreateTime(LocalDateTime createTime) {
        this.createTime = createTime;
    }
}
