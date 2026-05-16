package org.detector.qweovodetect;

import org.detector.qweovodetect.server.Socks5Server;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class QweovodetectApplication implements CommandLineRunner {

    private final Socks5Server server;

    public QweovodetectApplication(Socks5Server server) {
        this.server = server;
    }

    public static void main(String[] args) {
        SpringApplication.run(QweovodetectApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        server.start();
    }
}