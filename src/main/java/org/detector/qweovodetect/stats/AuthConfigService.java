package org.detector.qweovodetect.stats;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

@Service
public class AuthConfigService {

    private static final Path CONFIG_PATH = Path.of("cfg");
    private static final String PLACEHOLDER_USERNAME = "admin";
    private static final String PLACEHOLDER_PASSWORD = "password";

    private final ObjectMapper objectMapper;
    private final PasswordEncoder passwordEncoder;
    private AppConfig cachedConfig;

    public AuthConfigService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        this.objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        this.cachedConfig = loadOrCreate();
    }

    public synchronized boolean matches(String username, String password) {
        if (username == null || password == null) {
            return false;
        }
        AuthConfig auth = getConfig().auth();
        return auth.username().equals(username)
                && passwordEncoder.matches(password, auth.passwordHash());
    }

    public synchronized String currentUsername() {
        return getConfig().auth().username();
    }

    public synchronized DatabaseConfig currentDatabase() {
        return getConfig().database();
    }

    public synchronized boolean isFirstStartup() {
        return getConfig().firstStartup();
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

        AppConfig current = getConfig();
        AuthConfig nextAuth = new AuthConfig(newUsername.trim(), passwordEncoder.encode(newPassword));
        cachedConfig = current.withAuth(nextAuth);
        write(cachedConfig);
        return nextAuth;
    }

    public synchronized DatabaseConfig saveDatabase(DatabaseConfig database, AuthConfig initialAuth, boolean finishFirstStartup) {
        DatabaseConfig normalized = normalizeDatabase(database);
        AppConfig current = getConfig();
        AuthConfig nextAuth = current.auth();
        if (current.firstStartup()) {
            if (initialAuth == null
                    || initialAuth.username() == null
                    || initialAuth.username().isBlank()
                    || initialAuth.passwordHash() == null
                    || initialAuth.passwordHash().isBlank()) {
                throw new IllegalArgumentException("请设置初始用户名和密码");
            }
            nextAuth = new AuthConfig(initialAuth.username().trim(), passwordEncoder.encode(initialAuth.passwordHash()));
        }
        cachedConfig = new AppConfig(
                finishFirstStartup ? false : current.firstStartup(),
                nextAuth,
                normalized);
        write(cachedConfig);
        return normalized;
    }

    public void validateDatabaseConnection(DatabaseConfig database) {
        DatabaseConfig normalized = normalizeDatabase(database);
        if (!"MYSQL".equalsIgnoreCase(normalized.type())) {
            return;
        }

        String url = mysqlJdbcUrl(normalized);
        try {
            DriverManager.setLoginTimeout(5);
            try (Connection connection = DriverManager.getConnection(
                    url,
                    normalized.username(),
                    normalized.password() == null ? "" : normalized.password());
                 Statement statement = connection.createStatement()) {
                statement.execute("SELECT 1");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("MySQL 连接失败，请检查地址、端口、数据库名、用户名和密码：" + e.getMessage());
        }
    }

    public synchronized boolean verifyOwner(String username, String password) {
        return matches(username, password);
    }

    private AppConfig getConfig() {
        if (cachedConfig == null) {
            cachedConfig = loadOrCreate();
        }
        return cachedConfig;
    }

    private AppConfig loadOrCreate() {
        if (Files.exists(CONFIG_PATH)) {
            try {
                JsonNode root = objectMapper.readTree(CONFIG_PATH.toFile());
                AppConfig config = parseConfig(root);
                if (isValid(config)) {
                    if (!root.has("auth") || !root.has("database") || !root.has("firstStartup")) {
                        write(config);
                    }
                    return config;
                }
            } catch (IOException ignored) {
            }
        }

        AppConfig defaultConfig = new AppConfig(
                true,
                new AuthConfig(PLACEHOLDER_USERNAME, passwordEncoder.encode(PLACEHOLDER_PASSWORD)),
                DatabaseConfig.h2Default());
        write(defaultConfig);
        return defaultConfig;
    }

    private AppConfig parseConfig(JsonNode root) throws IOException {
        if (root.has("auth")) {
            return objectMapper.treeToValue(root, AppConfig.class);
        }

        String username = text(root, "username", PLACEHOLDER_USERNAME);
        String passwordHash = text(root, "passwordHash", passwordEncoder.encode(PLACEHOLDER_PASSWORD));
        return new AppConfig(true, new AuthConfig(username, passwordHash), DatabaseConfig.h2Default());
    }

    private boolean isValid(AppConfig config) {
        return config != null
                && config.auth() != null
                && config.auth().username() != null
                && !config.auth().username().isBlank()
                && config.auth().passwordHash() != null
                && !config.auth().passwordHash().isBlank()
                && config.database() != null;
    }

    private DatabaseConfig normalizeDatabase(DatabaseConfig database) {
        if (database == null || database.type() == null || database.type().isBlank()) {
            return DatabaseConfig.h2Default();
        }

        String type = database.type().trim().toUpperCase();
        if ("H2".equals(type)) {
            String path = blankToDefault(database.path(), "./data/socks5_stats");
            return new DatabaseConfig("H2", path, null, null, null, null, null);
        }

        if (!"MYSQL".equals(type)) {
            throw new IllegalArgumentException("不支持的数据库类型");
        }

        String host = blankToDefault(database.host(), "127.0.0.1");
        int port = database.port() == null ? 3306 : database.port();
        String databaseName = database.databaseName();
        String username = database.username();
        if (databaseName == null || databaseName.isBlank()) {
            throw new IllegalArgumentException("MySQL 数据库名不能为空");
        }
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("MySQL 用户名不能为空");
        }

        return new DatabaseConfig(
                "MYSQL",
                null,
                host,
                port,
                databaseName.trim(),
                username.trim(),
                database.password() == null ? "" : database.password());
    }

    private String text(JsonNode node, String field, String fallback) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? fallback : value.asText(fallback);
    }

    private String blankToDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    public static String mysqlJdbcUrl(DatabaseConfig database) {
        String host = database.host() == null || database.host().isBlank() ? "127.0.0.1" : database.host();
        int port = database.port() == null ? 3306 : database.port();
        return "jdbc:mysql://" + host + ":" + port + "/" + database.databaseName()
                + "?useUnicode=true&characterEncoding=utf8&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=Asia/Shanghai&connectTimeout=5000&socketTimeout=5000";
    }

    private void write(AppConfig config) {
        try {
            objectMapper.writeValue(CONFIG_PATH.toFile(), config);
        } catch (IOException e) {
            throw new IllegalStateException("写入配置失败", e);
        }
    }

    public record AppConfig(boolean firstStartup, AuthConfig auth, DatabaseConfig database) {
        public AppConfig withAuth(AuthConfig nextAuth) {
            return new AppConfig(firstStartup, nextAuth, database);
        }
    }

    public record AuthConfig(String username, String passwordHash) {
    }

    public record DatabaseConfig(String type,
                                 String path,
                                 String host,
                                 Integer port,
                                 String databaseName,
                                 String username,
                                 String password) {
        public static DatabaseConfig h2Default() {
            return new DatabaseConfig("H2", "./data/socks5_stats", null, null, null, null, null);
        }
    }
}
