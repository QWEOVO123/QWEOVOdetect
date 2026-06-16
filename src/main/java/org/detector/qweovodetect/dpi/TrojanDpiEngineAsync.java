package org.detector.qweovodetect.dpi;

import io.netty.buffer.ByteBuf;
import org.detector.qweovodetect.stats.ForensicsService;
import org.detector.qweovodetect.stats.StatsService;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class TrojanDpiEngineAsync {

    private static final byte[] CCS = {20, 3, 3, 0, 1, 1};
    private static final int DIR_UPLOAD = 0;
    private static final int DIR_DOWNLOAD = 1;

    private static final Map<Integer, FlowState> states = new ConcurrentHashMap<>();
    private static final int MAX_STATE_ENTRIES = 8192;
    private static final long STATE_TTL_MS = 180_000;
    private static final long CLEANUP_INTERVAL_MS = 60_000;
    private static final ScheduledExecutorService CLEANUP_EXECUTOR = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "trojan-dpi-state-cleanup");
        thread.setDaemon(true);
        return thread;
    });

    static {
        CLEANUP_EXECUTOR.scheduleWithFixedDelay(
                () -> cleanupExpired(System.currentTimeMillis()),
                CLEANUP_INTERVAL_MS,
                CLEANUP_INTERVAL_MS,
                TimeUnit.MILLISECONDS);
    }

    public static void inspect(ByteBuf buf,
                               String clientIp,
                               int listenPort,
                               String targetIp,
                               int chanId,
                               int dir) {
        if (buf == null || !buf.isReadable()) {
            return;
        }

        FlowState state = lookupState(chanId);
        if (state == null) {
            return;
        }
        TrojanHit hit;
        synchronized (state) {
            state.lastSeen = System.currentTimeMillis();
            if (state.finished) {
                return;
            }

            if (dir == DIR_UPLOAD) {
                hit = inspectUpload(state, buf);
            } else if (dir == DIR_DOWNLOAD) {
                hit = inspectDownload(state, buf);
            } else {
                return;
            }

            if (hit == null) {
                return;
            }

            state.finished = true;
        }

        DpiTaskExecutor.executeDb(() -> saveTrojan(clientIp, listenPort, targetIp, hit));
        recordForensics(clientIp, listenPort, targetIp, hit);
    }

    private static TrojanHit inspectUpload(FlowState state, ByteBuf buf) {
        if (state.uploadCount == 0 && startsWith(buf, CCS)) {
            state.uploading = true;
        }

        if (state.uploading) {
            state.uploadCount += buf.readableBytes();
        }

        if (state.downloading) {
            state.downloading = false;
            if (isTrojanSize(state.uploadCount, state.downloadCount)) {
                return new TrojanHit(state.uploadCount, state.downloadCount);
            }
        }

        if (!state.downloading && state.downloadCount != 0) {
            state.finished = true;
        }

        return null;
    }

    private static TrojanHit inspectDownload(FlowState state, ByteBuf buf) {
        if (state.uploading) {
            state.uploading = false;
            state.downloading = true;
        }

        if (state.downloading) {
            state.downloadCount += buf.readableBytes();
        }

        return null;
    }

    private static boolean startsWith(ByteBuf buf, byte[] prefix) {
        if (buf.readableBytes() < prefix.length) {
            return false;
        }

        int readerIndex = buf.readerIndex();
        for (int i = 0; i < prefix.length; i++) {
            if (buf.getByte(readerIndex + i) != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static boolean isTrojanSize(int uploadCount, int downloadCount) {
        return uploadCount >= 650 && uploadCount <= 750
                && ((downloadCount >= 170 && downloadCount <= 180)
                || (downloadCount >= 3000 && downloadCount <= 7500));
    }

    private static void saveTrojan(String clientIp, int listenPort, String targetIp, TrojanHit hit) {
        try {
            StatsService statsService = SpringContextHolder.getBean(StatsService.class);
            if (statsService != null) {
                statsService.saveTrojan(clientIp, listenPort, targetIp, hit.uploadBytes(), hit.downloadBytes());
            }
        } catch (Exception e) {
            System.out.println("[Trojan] save failed: " + e.getMessage());
        }
    }

    private static void recordForensics(String clientIp, int listenPort, String targetIp, TrojanHit hit) {
        try {
            ForensicsService forensicsService = SpringContextHolder.getBean(ForensicsService.class);
            if (forensicsService != null) {
                forensicsService.recordTrojan(listenPort, clientIp, targetIp, hit.uploadBytes(), hit.downloadBytes());
            }
        } catch (Exception ignored) {
        }
    }

    public static void cleanup(int chanId) {
        states.remove(chanId);
    }

    private static FlowState lookupState(int chanId) {
        FlowState existing = states.get(chanId);
        if (existing != null) {
            existing.lastSeen = System.currentTimeMillis();
            return existing;
        }

        long now = System.currentTimeMillis();
        if (states.size() >= MAX_STATE_ENTRIES) {
            cleanupExpired(now);
            if (states.size() >= MAX_STATE_ENTRIES) {
                return null;
            }
        }

        FlowState created = new FlowState(now);
        FlowState previous = states.putIfAbsent(chanId, created);
        return previous == null ? created : previous;
    }

    private static void cleanupExpired(long now) {
        states.entrySet().removeIf(entry -> now - entry.getValue().lastSeen > STATE_TTL_MS);
    }

    private static class FlowState {
        private volatile long lastSeen;
        private boolean uploading;
        private int uploadCount;
        private boolean downloading;
        private int downloadCount;
        private boolean finished;

        private FlowState(long lastSeen) {
            this.lastSeen = lastSeen;
        }
    }

    private record TrojanHit(int uploadBytes, int downloadBytes) {
    }
}
