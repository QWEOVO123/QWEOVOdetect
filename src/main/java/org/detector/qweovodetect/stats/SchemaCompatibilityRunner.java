package org.detector.qweovodetect.stats;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class SchemaCompatibilityRunner implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;

    public SchemaCompatibilityRunner(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            jdbcTemplate.execute("ALTER TABLE risk_targets DROP CONSTRAINT IF EXISTS uk_risk_protocol_target");
        } catch (Exception ignored) {
        }
        try {
            jdbcTemplate.update("UPDATE sni_logs SET protocol = 'TLS' WHERE protocol IS NULL");
        } catch (Exception ignored) {
        }
    }
}
