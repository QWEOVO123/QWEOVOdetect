package org.detector.qweovodetect.stats;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/setup")
public class SetupController {

    private final AuthConfigService authConfigService;

    public SetupController(AuthConfigService authConfigService) {
        this.authConfigService = authConfigService;
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        return Map.of(
                "firstStartup", authConfigService.isFirstStartup(),
                "database", publicDatabase(authConfigService.currentDatabase()),
                "api", publicApi(authConfigService.currentApi()),
                "inbounds", publicInbounds(authConfigService.currentInbounds())
        );
    }

    @PostMapping("/database")
    public ResponseEntity<?> saveDatabase(@RequestBody DatabaseSetupRequest request) {
        try {
            boolean firstStartup = authConfigService.isFirstStartup();
            if (!firstStartup && !authConfigService.verifyOwner(request.oldUsername(), request.oldPassword())) {
                return ResponseEntity.status(403).body(Map.of("error", "原用户名或密码错误"));
            }

            authConfigService.validateDatabaseConnection(request.database());

            AuthConfigService.DatabaseConfig previous = authConfigService.currentDatabase();
            AuthConfigService.ApiConfig previousApi = authConfigService.currentApi();
            var previousInbounds = authConfigService.currentInbounds();
            AuthConfigService.AuthConfig initialAuth = null;
            if (firstStartup) {
                initialAuth = new AuthConfigService.AuthConfig(request.initialUsername(), request.initialPassword());
            }
            AuthConfigService.AppConfig saved = authConfigService.saveRuntimeConfig(
                    request.database(),
                    request.api(),
                    request.inbounds(),
                    initialAuth,
                    true);
            boolean requiresRestart = !sameDatabase(previous, saved.database())
                    || !publicApi(previousApi).equals(publicApi(saved.api()))
                    || !publicInbounds(previousInbounds).equals(publicInbounds(saved.inbounds()));

            return ResponseEntity.ok(Map.of(
                    "firstStartup", false,
                    "requiresRestart", requiresRestart,
                    "database", publicDatabase(saved.database()),
                    "api", publicApi(saved.api()),
                    "inbounds", publicInbounds(saved.inbounds())
            ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/runtime")
    public ResponseEntity<?> saveRuntime(@RequestBody RuntimeSetupRequest request) {
        try {
            if (!authConfigService.verifyOwner(request.oldUsername(), request.oldPassword())) {
                return ResponseEntity.status(403).body(Map.of("error", "原用户名或密码错误"));
            }

            AuthConfigService.ApiConfig previousApi = authConfigService.currentApi();
            var previousInbounds = authConfigService.currentInbounds();
            AuthConfigService.AppConfig saved = authConfigService.saveRuntimeConfig(
                    authConfigService.currentDatabase(),
                    request.api(),
                    request.inbounds(),
                    null,
                    false);
            boolean requiresRestart = !publicApi(previousApi).equals(publicApi(saved.api()))
                    || !publicInbounds(previousInbounds).equals(publicInbounds(saved.inbounds()));

            return ResponseEntity.ok(Map.of(
                    "requiresRestart", requiresRestart,
                    "api", publicApi(saved.api()),
                    "inbounds", publicInbounds(saved.inbounds())
            ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    private boolean sameDatabase(AuthConfigService.DatabaseConfig left, AuthConfigService.DatabaseConfig right) {
        return publicDatabase(left).equals(publicDatabase(right));
    }

    private Map<String, Object> publicDatabase(AuthConfigService.DatabaseConfig database) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", database.type());
        map.put("path", database.path());
        map.put("host", database.host());
        map.put("port", database.port());
        map.put("databaseName", database.databaseName());
        map.put("username", database.username());
        return map;
    }

    private Map<String, Object> publicApi(AuthConfigService.ApiConfig api) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("address", api.address());
        map.put("port", api.port());
        return map;
    }

    private java.util.List<Map<String, Object>> publicInbounds(java.util.List<AuthConfigService.InboundConfig> inbounds) {
        return inbounds.stream().map(inbound -> {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("id", inbound.id());
            map.put("nickname", inbound.nickname());
            map.put("port", inbound.port());
            map.put("enabled", inbound.enabled());
            map.put("authEnabled", inbound.authEnabled());
            map.put("username", inbound.username());
            return map;
        }).toList();
    }

    public record DatabaseSetupRequest(String oldUsername,
                                       String oldPassword,
                                       String initialUsername,
                                       String initialPassword,
                                       AuthConfigService.DatabaseConfig database,
                                       AuthConfigService.ApiConfig api,
                                       java.util.List<AuthConfigService.InboundUpdate> inbounds) {
    }

    public record RuntimeSetupRequest(String oldUsername,
                                      String oldPassword,
                                      AuthConfigService.ApiConfig api,
                                      java.util.List<AuthConfigService.InboundUpdate> inbounds) {
    }
}
