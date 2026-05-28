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
                "database", publicDatabase(authConfigService.currentDatabase())
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
            AuthConfigService.AuthConfig initialAuth = null;
            if (firstStartup) {
                initialAuth = new AuthConfigService.AuthConfig(request.initialUsername(), request.initialPassword());
            }
            AuthConfigService.DatabaseConfig saved = authConfigService.saveDatabase(request.database(), initialAuth, true);
            boolean requiresRestart = !sameDatabase(previous, saved);

            return ResponseEntity.ok(Map.of(
                    "firstStartup", false,
                    "requiresRestart", requiresRestart,
                    "database", publicDatabase(saved)
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

    public record DatabaseSetupRequest(String oldUsername,
                                       String oldPassword,
                                       String initialUsername,
                                       String initialPassword,
                                       AuthConfigService.DatabaseConfig database) {
    }
}
