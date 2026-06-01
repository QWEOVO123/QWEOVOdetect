package org.detector.qweovodetect.dpi;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
public class TemporaryTargetBlocklist {

    private static final long BLOCK_TTL_MS = TimeUnit.MINUTES.toMillis(2);
    private static final long CLEANUP_INTERVAL_MS = TimeUnit.SECONDS.toMillis(30);
    private static final int MAX_ENTRIES = 65_536;

    private final Map<String, Long> blockedTargets = new ConcurrentHashMap<>();
    private final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "temporary-target-blocklist-cleanup");
        thread.setDaemon(true);
        return thread;
    });

    public TemporaryTargetBlocklist() {
        cleanupExecutor.scheduleWithFixedDelay(
                () -> cleanupExpired(System.currentTimeMillis()),
                CLEANUP_INTERVAL_MS,
                CLEANUP_INTERVAL_MS,
                TimeUnit.MILLISECONDS);
    }

    public void block(String clientIp, String targetHost, int targetPort) {
        if (clientIp == null || clientIp.isBlank() || targetHost == null || targetHost.isBlank()) {
            return;
        }

        long now = System.currentTimeMillis();
        if (blockedTargets.size() >= MAX_ENTRIES) {
            cleanupExpired(now);
            if (blockedTargets.size() >= MAX_ENTRIES) {
                return;
            }
        }

        blockedTargets.put(key(clientIp, targetHost, targetPort), now + BLOCK_TTL_MS);
    }

    public boolean isBlocked(String clientIp, String targetHost, int targetPort) {
        Long expiresAt = blockedTargets.get(key(clientIp, targetHost, targetPort));
        if (expiresAt == null) {
            return false;
        }
        if (expiresAt <= System.currentTimeMillis()) {
            blockedTargets.remove(key(clientIp, targetHost, targetPort), expiresAt);
            return false;
        }
        return true;
    }

    public int size() {
        cleanupExpired(System.currentTimeMillis());
        return blockedTargets.size();
    }

    public void clear() {
        blockedTargets.clear();
    }

    private void cleanupExpired(long now) {
        blockedTargets.entrySet().removeIf(entry -> entry.getValue() <= now);
    }

    private String key(String clientIp, String targetHost, int targetPort) {
        return clientIp + "|" + targetHost + ":" + targetPort;
    }
}
