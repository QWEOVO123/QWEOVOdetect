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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

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

    public synchronized ApiConfig currentApi() {
        return getConfig().api();
    }

    public synchronized List<InboundConfig> currentInbounds() {
        return getConfig().inbounds();
    }

    public synchronized boolean isFirstStartup() {
        return getConfig().firstStartup();
    }

    public synchronized boolean isPendingRestart() {
        return getConfig().pendingRestart();
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
        return saveRuntimeConfig(database, null, null, initialAuth, finishFirstStartup).database();
    }

    public synchronized AppConfig saveRuntimeConfig(DatabaseConfig database,
                                                    ApiConfig api,
                                                    List<InboundUpdate> inboundUpdates,
                                                    AuthConfig initialAuth,
                                                    boolean finishFirstStartup) {
        AppConfig next = buildRuntimeConfig(database, api, inboundUpdates, initialAuth, finishFirstStartup);
        cachedConfig = next;
        write(cachedConfig);
        return cachedConfig;
    }

    public synchronized AppConfig previewRuntimeConfig(DatabaseConfig database,
                                                       ApiConfig api,
                                                       List<InboundUpdate> inboundUpdates,
                                                       AuthConfig initialAuth,
                                                       boolean finishFirstStartup) {
        return buildRuntimeConfig(database, api, inboundUpdates, initialAuth, finishFirstStartup);
    }

    private AppConfig buildRuntimeConfig(DatabaseConfig database,
                                         ApiConfig api,
                                         List<InboundUpdate> inboundUpdates,
                                         AuthConfig initialAuth,
                                         boolean finishFirstStartup) {
        DatabaseConfig normalized = normalizeDatabase(database);
        ApiConfig normalizedApi = api == null ? getConfig().api() : normalizeApi(api);
        List<InboundConfig> normalizedInbounds = inboundUpdates == null
                ? getConfig().inbounds()
                : normalizeInbounds(inboundUpdates, getConfig().inbounds());
        validateRuntimePorts(normalizedApi, normalizedInbounds);
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
        return new AppConfig(
                finishFirstStartup ? false : current.firstStartup(),
                current.pendingRestart()
                        || finishFirstStartup
                        || !sameDatabaseConfig(current.database(), normalized)
                        || !sameApiConfig(current.api(), normalizedApi),
                nextAuth,
                normalized,
                normalizedApi,
                normalizedInbounds);
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
                AppConfig config = normalizeConfig(parseConfig(root));
                if (isValid(config)) {
                    if (config.pendingRestart()) {
                        config = config.withPendingRestart(false);
                        write(config);
                    }
                    if (!root.has("auth") || !root.has("database") || !root.has("firstStartup")
                            || !root.has("pendingRestart") || !root.has("api") || !root.has("inbounds")) {
                        write(config);
                    }
                    return config;
                }
            } catch (IOException ignored) {
            }
        }

        AppConfig defaultConfig = new AppConfig(
                true,
                false,
                new AuthConfig(PLACEHOLDER_USERNAME, passwordEncoder.encode(PLACEHOLDER_PASSWORD)),
                DatabaseConfig.h2Default(),
                ApiConfig.defaultApi(),
                List.of(InboundConfig.defaultInbound()));
        write(defaultConfig);
        return defaultConfig;
    }

    private AppConfig parseConfig(JsonNode root) throws IOException {
        if (root.has("auth")) {
            AppConfig parsed = objectMapper.treeToValue(root, AppConfig.class);
            return normalizeConfig(parsed);
        }

        String username = text(root, "username", PLACEHOLDER_USERNAME);
        String passwordHash = text(root, "passwordHash", passwordEncoder.encode(PLACEHOLDER_PASSWORD));
        return new AppConfig(true, false, new AuthConfig(username, passwordHash),
                DatabaseConfig.h2Default(), ApiConfig.defaultApi(), List.of(InboundConfig.defaultInbound()));
    }

    private AppConfig normalizeConfig(AppConfig config) {
        if (config == null) {
            return new AppConfig(true,
                    false,
                    new AuthConfig(PLACEHOLDER_USERNAME, passwordEncoder.encode(PLACEHOLDER_PASSWORD)),
                    DatabaseConfig.h2Default(),
                    ApiConfig.defaultApi(),
                    List.of(InboundConfig.defaultInbound()));
        }
        return new AppConfig(
                config.firstStartup(),
                config.pendingRestart(),
                config.auth(),
                config.database() == null ? DatabaseConfig.h2Default() : normalizeDatabase(config.database()),
                config.api() == null ? ApiConfig.defaultApi() : normalizeApi(config.api()),
                config.inbounds() == null || config.inbounds().isEmpty()
                        ? List.of(InboundConfig.defaultInbound())
                        : normalizeStoredInbounds(config.inbounds()));
    }

    private boolean isValid(AppConfig config) {
        return config != null
                && config.auth() != null
                && config.auth().username() != null
                && !config.auth().username().isBlank()
                && config.auth().passwordHash() != null
                && !config.auth().passwordHash().isBlank()
                && config.database() != null
                && config.api() != null
                && config.inbounds() != null
                && !config.inbounds().isEmpty();
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

    private ApiConfig normalizeApi(ApiConfig api) {
        int port = api.port() == null ? 8080 : api.port();
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("API 端口必须在 1-65535 之间");
        }
        String address = blankToDefault(api.address(), "127.0.0.1");
        return new ApiConfig(address, port);
    }

    private List<InboundConfig> normalizeStoredInbounds(List<InboundConfig> inbounds) {
        List<Integer> ports = new ArrayList<>();
        return inbounds.stream().map(inbound -> {
            int port = inbound.port() == null ? 1080 : inbound.port();
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("入站端口必须在 1-65535 之间");
            }
            if (ports.contains(port)) {
                throw new IllegalArgumentException("入站端口不能重复：" + port);
            }
            ports.add(port);
            boolean authEnabled = inbound.authEnabled();
            String username = inbound.username() == null ? "" : inbound.username().trim();
            String passwordHash = inbound.passwordHash() == null ? "" : inbound.passwordHash();
            if (authEnabled && (username.isBlank() || passwordHash.isBlank())) {
                throw new IllegalArgumentException("启用 SOCKS5 认证时必须配置用户名和密码");
            }
            return new InboundConfig(
                    blankToDefault(inbound.id(), UUID.randomUUID().toString()),
                    blankToDefault(inbound.nickname(), "入站 " + port),
                    port,
                    inbound.enabled(),
                    authEnabled,
                    username,
                    passwordHash);
        }).toList();
    }

    private List<InboundConfig> normalizeInbounds(List<InboundUpdate> updates, List<InboundConfig> previous) {
        if (updates == null || updates.isEmpty()) {
            throw new IllegalArgumentException("至少需要配置一个入站端口");
        }

        List<InboundConfig> result = new ArrayList<>();
        for (InboundUpdate update : updates) {
            int port = update.port() == null ? 1080 : update.port();
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("入站端口必须在 1-65535 之间");
            }
            if (result.stream().anyMatch(inbound -> inbound.port() == port)) {
                throw new IllegalArgumentException("入站端口不能重复：" + port);
            }

            InboundConfig old = findInbound(previous, update.id(), port);
            boolean authEnabled = update.authEnabled();
            String username = update.username() == null ? "" : update.username().trim();
            String passwordHash = old == null ? "" : old.passwordHash();
            if (authEnabled) {
                if (username.isBlank()) {
                    throw new IllegalArgumentException("启用 SOCKS5 认证时必须配置用户名");
                }
                if (update.password() != null && !update.password().isBlank()) {
                    passwordHash = passwordEncoder.encode(update.password());
                }
                if (passwordHash.isBlank()) {
                    throw new IllegalArgumentException("启用 SOCKS5 认证时必须配置密码");
                }
            } else {
                username = "";
                passwordHash = "";
            }

            result.add(new InboundConfig(
                    blankToDefault(update.id(), UUID.randomUUID().toString()),
                    blankToDefault(update.nickname(), "入站 " + port),
                    port,
                    update.enabled(),
                    authEnabled,
                    username,
                    passwordHash));
        }
        return result;
    }

    private void validateRuntimePorts(ApiConfig api, List<InboundConfig> inbounds) {
        if (inbounds.stream().noneMatch(InboundConfig::enabled)) {
            throw new IllegalArgumentException("至少需要启用一个入站端口");
        }
        for (InboundConfig inbound : inbounds) {
            if (inbound.enabled() && inbound.port().equals(api.port())) {
                throw new IllegalArgumentException("API 端口不能和已启用入站端口相同：" + api.port());
            }
        }
    }

    private boolean sameDatabaseConfig(DatabaseConfig left, DatabaseConfig right) {
        return left != null && right != null
                && Objects.equals(left.type(), right.type())
                && Objects.equals(left.path(), right.path())
                && Objects.equals(left.host(), right.host())
                && Objects.equals(left.port(), right.port())
                && Objects.equals(left.databaseName(), right.databaseName())
                && Objects.equals(left.username(), right.username())
                && Objects.equals(left.password(), right.password());
    }

    private boolean sameApiConfig(ApiConfig left, ApiConfig right) {
        return left != null && right != null
                && Objects.equals(left.address(), right.address())
                && Objects.equals(left.port(), right.port());
    }

    private InboundConfig findInbound(List<InboundConfig> previous, String id, int port) {
        if (previous == null) {
            return null;
        }
        return previous.stream()
                .filter(inbound -> (id != null && id.equals(inbound.id())) || inbound.port() == port)
                .findFirst()
                .orElse(null);
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

    public record AppConfig(boolean firstStartup,
                            boolean pendingRestart,
                            AuthConfig auth,
                            DatabaseConfig database,
                            ApiConfig api,
                            List<InboundConfig> inbounds) {
        public AppConfig withAuth(AuthConfig nextAuth) {
            return new AppConfig(firstStartup, pendingRestart, nextAuth, database, api, inbounds);
        }

        public AppConfig withPendingRestart(boolean nextPendingRestart) {
            return new AppConfig(firstStartup, nextPendingRestart, auth, database, api, inbounds);
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

    public record ApiConfig(String address, Integer port) {
        public static ApiConfig defaultApi() {
            return new ApiConfig("127.0.0.1", 8080);
        }
    }

    public record InboundConfig(String id,
                                String nickname,
                                Integer port,
                                boolean enabled,
                                boolean authEnabled,
                                String username,
                                String passwordHash) {
        public static InboundConfig defaultInbound() {
            return new InboundConfig(UUID.randomUUID().toString(), "默认入站", 1080, true, false, "", "");
        }
    }

    public record InboundUpdate(String id,
                                String nickname,
                                Integer port,
                                boolean enabled,
                                boolean authEnabled,
                                String username,
                                String password) {
    }
}
