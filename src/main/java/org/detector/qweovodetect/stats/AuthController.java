package org.detector.qweovodetect.stats;

import org.detector.qweovodetect.config.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    //账号
    private static final String ADMIN_USERNAME = "bx20061015";
    //密码哈希值
    private static final String ADMIN_PASSWORD_HASH =
            "$2a$10$eJq5T8Y8OPx0mPApSpNWt.PtzOLJ6krj1zsiP/y9ievN/RhvxdGli";

    public AuthController(JwtUtil jwtUtil, PasswordEncoder passwordEncoder) {
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        if (ADMIN_USERNAME.equals(username) &&
                passwordEncoder.matches(password, ADMIN_PASSWORD_HASH)) {

            String token = jwtUtil.generateToken(username);
            return ResponseEntity.ok(Map.of(
                    "token", token,
                    "username", username
            ));
        }

        return ResponseEntity.status(401).body(Map.of(
                "error", "用户名或密码错误"
        ));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(@RequestHeader("Authorization") String auth) {
        String token = auth.replace("Bearer ", "");
        String username = jwtUtil.getUsername(token);
        return ResponseEntity.ok(Map.of("username", username));
    }
}