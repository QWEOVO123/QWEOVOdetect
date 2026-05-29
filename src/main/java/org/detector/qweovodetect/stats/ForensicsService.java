package org.detector.qweovodetect.stats;

import org.springframework.stereotype.Service;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

@Service
public class ForensicsService {

    private static final Path FORENSICS_DIR = Path.of("forensics");
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final int MIN_DURATION_MINUTES = 1;
    private static final int MAX_DURATION_MINUTES = 1440;

    private final Map<Integer, Session> sessions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "forensics-timer");
        thread.setDaemon(true);
        return thread;
    });

    public synchronized Map<String, Object> start(int listenPort, String fileName, int durationMinutes) {
        if (listenPort < 1 || listenPort > 65535) {
            throw new IllegalArgumentException("端口必须在 1-65535 之间");
        }
        if (durationMinutes < MIN_DURATION_MINUTES || durationMinutes > MAX_DURATION_MINUTES) {
            throw new IllegalArgumentException("取证时长必须在 1-1440 分钟之间");
        }
        if (sessions.containsKey(listenPort)) {
            throw new IllegalArgumentException("该端口已经在取证中");
        }

        try {
            Files.createDirectories(FORENSICS_DIR);
            Path file = resolveFile(fileName);
            BufferedWriter writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);

            LocalDateTime startedAt = LocalDateTime.now();
            LocalDateTime expiresAt = startedAt.plusMinutes(durationMinutes);
            Session session = new Session(listenPort, file, startedAt, expiresAt, writer);
            ScheduledFuture<?> stopTask = scheduler.schedule(
                    () -> stop(listenPort),
                    durationMinutes,
                    TimeUnit.MINUTES);
            session.stopTask = stopTask;
            sessions.put(listenPort, session);
            session.write("# Forensics started port=" + listenPort
                    + " start=" + format(startedAt)
                    + " expires=" + format(expiresAt));
            return publicSession(session);
        } catch (IOException e) {
            throw new IllegalArgumentException("取证文件创建失败：" + e.getMessage());
        }
    }

    public synchronized boolean stop(int listenPort) {
        Session session = sessions.remove(listenPort);
        if (session == null) {
            return false;
        }
        if (session.stopTask != null) {
            session.stopTask.cancel(false);
        }
        session.close();
        return true;
    }

    public List<Map<String, Object>> listSessions() {
        return sessions.values().stream()
                .sorted(Comparator.comparingInt(Session::listenPort))
                .map(this::publicSession)
                .toList();
    }

    public void recordTls(int listenPort, String clientIp, String sni) {
        record(listenPort, "[TLS] port=%d client=%s sni=%s".formatted(listenPort, safe(clientIp), safe(sni)));
    }

    public void recordQuic(int listenPort, String clientIp, String targetHost, int targetPort, String sni) {
        record(listenPort, "[QUIC] port=%d client=%s target=%s:%d sni=%s"
                .formatted(listenPort, safe(clientIp), safe(targetHost), targetPort, safe(sni)));
    }

    public void recordTrojan(int listenPort, String clientIp, String targetIp, int uploadBytes, int downloadBytes) {
        record(listenPort, "[TROJAN] port=%d client=%s target=%s upload=%d download=%d"
                .formatted(listenPort, safe(clientIp), safe(targetIp), uploadBytes, downloadBytes));
    }

    public void recordSs(int listenPort, String clientIp, String targetIp) {
        record(listenPort, "[SS] port=%d client=%s target=%s"
                .formatted(listenPort, safe(clientIp), safe(targetIp)));
    }

    private void record(int listenPort, String event) {
        Session session = sessions.get(listenPort);
        if (session == null) {
            return;
        }
        session.write(format(LocalDateTime.now()) + " " + event);
    }

    private Path resolveFile(String fileName) {
        String name = fileName == null ? "" : fileName.trim();
        if (name.isBlank()) {
            throw new IllegalArgumentException("请填写取证文件名");
        }
        if (name.contains("/") || name.contains("\\") || name.contains("..")) {
            throw new IllegalArgumentException("文件名不能包含路径");
        }
        name = name.replaceAll("[^a-zA-Z0-9._-]", "_");
        if (!name.toLowerCase().endsWith(".txt")) {
            name += ".txt";
        }
        if (name.length() > 160) {
            throw new IllegalArgumentException("文件名过长");
        }
        return FORENSICS_DIR.resolve(name).normalize();
    }

    private Map<String, Object> publicSession(Session session) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("listenPort", session.listenPort());
        map.put("filePath", session.file().toAbsolutePath().toString());
        map.put("fileName", session.file().getFileName().toString());
        map.put("startedAt", session.startedAt());
        map.put("expiresAt", session.expiresAt());
        return map;
    }

    private static String format(LocalDateTime time) {
        return TIME_FORMATTER.format(time);
    }

    private static String safe(String value) {
        return value == null ? "" : value.replace('\r', '_').replace('\n', '_');
    }

    private static class Session {
        private final int listenPort;
        private final Path file;
        private final LocalDateTime startedAt;
        private final LocalDateTime expiresAt;
        private final BufferedWriter writer;
        private ScheduledFuture<?> stopTask;

        private Session(int listenPort, Path file, LocalDateTime startedAt, LocalDateTime expiresAt, BufferedWriter writer) {
            this.listenPort = listenPort;
            this.file = file;
            this.startedAt = startedAt;
            this.expiresAt = expiresAt;
            this.writer = writer;
        }

        private int listenPort() {
            return listenPort;
        }

        private Path file() {
            return file;
        }

        private LocalDateTime startedAt() {
            return startedAt;
        }

        private LocalDateTime expiresAt() {
            return expiresAt;
        }

        private synchronized void write(String line) {
            try {
                writer.write(line);
                writer.newLine();
                writer.flush();
            } catch (IOException ignored) {
            }
        }

        private synchronized void close() {
            try {
                write("# Forensics stopped port=" + listenPort + " stop=" + format(LocalDateTime.now()));
                writer.close();
            } catch (IOException ignored) {
            }
        }
    }
}
