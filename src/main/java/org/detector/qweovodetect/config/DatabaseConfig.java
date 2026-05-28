package org.detector.qweovodetect.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.detector.qweovodetect.stats.AuthConfigService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

@Configuration
public class DatabaseConfig {

    @Bean
    public DataSource dataSource(AuthConfigService authConfigService) {
        AuthConfigService.DatabaseConfig database = authConfigService.currentDatabase();

        HikariConfig config = new HikariConfig();
        config.setPoolName("QWEOVOdetectPool");
        config.setMaximumPoolSize(10);
        config.setMinimumIdle(1);

        if ("MYSQL".equalsIgnoreCase(database.type())) {
            config.setDriverClassName("com.mysql.cj.jdbc.Driver");
            config.setJdbcUrl(AuthConfigService.mysqlJdbcUrl(database));
            config.setUsername(database.username());
            config.setPassword(database.password() == null ? "" : database.password());
        } else {
            String path = database.path() == null || database.path().isBlank()
                    ? "./data/socks5_stats"
                    : database.path();
            config.setDriverClassName("org.h2.Driver");
            config.setJdbcUrl("jdbc:h2:file:" + path + ";AUTO_SERVER=TRUE");
            config.setUsername("sa");
            config.setPassword("");
        }

        return new HikariDataSource(config);
    }
}
