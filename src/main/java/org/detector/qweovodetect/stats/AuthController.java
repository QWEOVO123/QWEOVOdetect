package org.detector.qweovodetect.stats;

import org.detector.qweovodetect.config.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtUtil jwtUtil;
    private final AuthConfigService authConfigService;
    private final LoginRateLimiter loginRateLimiter;

    public AuthController(JwtUtil jwtUtil,
                          AuthConfigService authConfigService,
                          LoginRateLimiter loginRateLimiter) {
        this.jwtUtil = jwtUtil;
        this.authConfigService = authConfigService;
        this.loginRateLimiter = loginRateLimiter;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        if (authConfigService.isPendingRestart()) {
            return ResponseEntity.status(423).body(Map.of("error", "配置已保存，请重启后端服务后再登录"));
        }
        if (loginRateLimiter.isLimited()) {
            return ResponseEntity.status(429).body(Map.of(
                    "error", "登录尝试过于频繁，请稍后再试",
                    "retryAfterSeconds", loginRateLimiter.retryAfterSeconds()));
        }

        String username = body.get("username");
        String password = body.get("password");

        if (authConfigService.matches(username, password)) {
            loginRateLimiter.recordSuccess();
            String token = jwtUtil.generateToken(username);
            return ResponseEntity.ok(Map.of(
                    "token", token,
                    "username", username
            ));
        }

        loginRateLimiter.recordFailure();
        return ResponseEntity.status(401).body(Map.of("error", "用户名或密码错误"));
    }

    @PostMapping("/credentials")
    public ResponseEntity<?> changeCredentials(@RequestBody Map<String, String> body) {
        try {
            AuthConfigService.AuthConfig config = authConfigService.changeCredentials(
                    body.get("oldUsername"),
                    body.get("oldPassword"),
                    body.get("newUsername"),
                    body.get("newPassword"));

            String token = jwtUtil.generateToken(config.username());
            return ResponseEntity.ok(Map.of(
                    "token", token,
                    "username", config.username()
            ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(@RequestHeader("Authorization") String auth) {
        String token = auth.replace("Bearer ", "");
        if (!jwtUtil.validateToken(token)) {
            return ResponseEntity.status(401).body(Map.of("error", "Token 已失效"));
        }
        String username = jwtUtil.getUsername(token);
        return ResponseEntity.ok(Map.of("username", username));
    }
}
