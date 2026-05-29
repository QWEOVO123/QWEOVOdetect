package org.detector.qweovodetect;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.detector.qweovodetect.server.Socks5Server;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.nio.file.Files;
import java.nio.file.Path;

@SpringBootApplication
public class QweovodetectApplication implements CommandLineRunner {

    private final Socks5Server server;

    public QweovodetectApplication(Socks5Server server) {
        this.server = server;
    }

    public static void main(String[] args) {
        applyApiPortFromCfg();
        SpringApplication.run(QweovodetectApplication.class, args);
    }

    private static void applyApiPortFromCfg() {
        Path cfg = Path.of("cfg");
        if (!Files.exists(cfg)) {
            return;
        }
        try {
            JsonNode api = new ObjectMapper().readTree(cfg.toFile()).path("api");
            int port = api.path("port").asInt(8080);
            String address = api.path("address").asText("127.0.0.1");
            if (port >= 1 && port <= 65535) {
                System.setProperty("server.port", String.valueOf(port));
            }
            if (address != null && !address.isBlank()) {
                System.setProperty("server.address", address);
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public void run(String... args) throws Exception {
        server.start();
    }
}
