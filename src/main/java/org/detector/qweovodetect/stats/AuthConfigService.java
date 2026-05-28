package org.detector.qweovodetect.stats;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Service
public class AuthConfigService {

    private static final Path CONFIG_PATH = Path.of("cfg");
    private static final String DEFAULT_USERNAME = "admin";
    private static final String DEFAULT_PASSWORD = "password";

    private final ObjectMapper objectMapper;
    private final PasswordEncoder passwordEncoder;
    private AuthConfig cachedConfig;

    public AuthConfigService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        this.objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        this.cachedConfig = loadOrCreate();
    }

    public synchronized boolean matches(String username, String password) {
        if (username == null || password == null) {
            return false;
        }
        AuthConfig config = getConfig();
        return config.username().equals(username)
                && passwordEncoder.matches(password, config.passwordHash());
    }

    public synchronized String currentUsername() {
        return getConfig().username();
    }

    public synchronized AuthConfig changeCredentials(String oldUsername,
                                                     String oldPassword,
                                                     String newUsername,
                                                     String newPassword) {
        if (!matches(oldUsername, oldPassword)) {
            throw new IllegalArgumentException("原用户名或密码错误");
        }
        if (newUsername == null || newUsername.isBlank()) {
            throw new IllegalArgumentException("新用户名不能为空");
        }
        if (newPassword == null || newPassword.isBlank()) {
            throw new IllegalArgumentException("新密码不能为空");
        }

        AuthConfig next = new AuthConfig(newUsername.trim(), passwordEncoder.encode(newPassword));
        write(next);
        cachedConfig = next;
        return next;
    }

    private AuthConfig getConfig() {
        if (cachedConfig == null) {
            cachedConfig = loadOrCreate();
        }
        return cachedConfig;
    }

    private AuthConfig loadOrCreate() {
        if (Files.exists(CONFIG_PATH)) {
            try {
                AuthConfig config = objectMapper.readValue(CONFIG_PATH.toFile(), AuthConfig.class);
                if (config.username() != null && !config.username().isBlank()
                        && config.passwordHash() != null && !config.passwordHash().isBlank()) {
                    return config;
                }
            } catch (IOException ignored) {
            }
        }

        AuthConfig defaultConfig = new AuthConfig(DEFAULT_USERNAME, passwordEncoder.encode(DEFAULT_PASSWORD));
        write(defaultConfig);
        return defaultConfig;
    }

    private void write(AuthConfig config) {
        try {
            objectMapper.writeValue(CONFIG_PATH.toFile(), config);
        } catch (IOException e) {
            throw new IllegalStateException("写入认证配置失败", e);
        }
    }

    public record AuthConfig(String username, String passwordHash) {
    }
}
