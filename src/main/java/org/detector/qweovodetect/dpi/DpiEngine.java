package org.detector.qweovodetect.dpi;

import io.netty.buffer.ByteBuf;
import org.detector.qweovodetect.stats.BlockRuleService;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class DpiEngine {

    public static final int MAX_CHUNK_INSPECT = 1024;

    private static final Map<Integer, TlsSniParser> tlsParsers = new ConcurrentHashMap<>();
    private static final Map<Integer, Integer> inspectedBytes = new ConcurrentHashMap<>();
    private static final Map<Integer, Long> stateLastSeen = new ConcurrentHashMap<>();

    private static final int MAX_INSPECT = 8192;
    private static final int MAX_STATE_ENTRIES = 8192;
    private static final long STATE_TTL_MS = 180_000;
    private static final long CLEANUP_INTERVAL_MS = 60_000;
    private static final ScheduledExecutorService CLEANUP_EXECUTOR = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "tcp-dpi-state-cleanup");
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
        if (buf == null || !buf.isReadable() || !shouldInspect(chanId, dir)) {
            return;
        }

        int len = Math.min(buf.readableBytes(), MAX_CHUNK_INSPECT);
        byte[] data = new byte[len];
        buf.getBytes(buf.readerIndex(), data, 0, len);

        inspect(data, clientIp, listenPort, targetIp, chanId, dir);
    }

    public static boolean inspectAndShouldBlock(ByteBuf buf,
                                                String clientIp,
                                                int listenPort,
                                                String targetIp,
                                                int chanId,
                                                int dir) {
        if (buf == null || !buf.isReadable() || !shouldInspect(chanId, dir)) {
            return false;
        }

        int len = Math.min(buf.readableBytes(), MAX_CHUNK_INSPECT);
        byte[] data = new byte[len];
        buf.getBytes(buf.readerIndex(), data, 0, len);

        return inspectAndShouldBlock(data, clientIp, listenPort, targetIp, chanId, dir);
    }

    public static void inspect(byte[] data,
                               String clientIp,
                               int listenPort,
                               String targetIp,
                               int chanId,
                               int dir) {
        inspectAndShouldBlock(data, clientIp, listenPort, targetIp, chanId, dir);
    }

    public static boolean inspectAndShouldBlock(byte[] data,
                                                String clientIp,
                                                int listenPort,
                                                String targetIp,
                                                int chanId,
                                                int dir) {
        if (data == null || data.length == 0 || !shouldInspect(chanId, dir)) {
            return false;
        }

        inspectedBytes.merge(chanId, data.length, Integer::sum);

        String host = HttpHostParser.parse(data, clientIp);
        if (isBlocked(host, "HTTP", clientIp, listenPort, targetIp)) {
            return true;
        }

        String sni = feedTls(chanId, data, clientIp, listenPort);
        if (isBlocked(sni, "TLS", clientIp, listenPort, targetIp)) {
            return true;
        }

        SSDetector.detect(data, clientIp, listenPort, targetIp, chanId);
        return false;
    }

    public static boolean shouldInspect(int chanId, int dir) {
        if (dir != 0) {
            return false;
        }
        if (!touchState(chanId)) {
            return false;
        }
        return inspectedBytes.getOrDefault(chanId, 0) < MAX_INSPECT;
    }

    private static String feedTls(int chanId, byte[] data, String clientIp, int listenPort) {
        return tlsParsers
                .computeIfAbsent(chanId, k -> new TlsSniParser())
                .feed(data, clientIp, listenPort);
    }

    private static boolean isBlocked(String domain,
                                     String protocol,
                                     String clientIp,
                                     int listenPort,
                                     String targetIp) {
        if (domain == null || domain.isBlank()) {
            return false;
        }
        try {
            BlockRuleService blockRuleService = SpringContextHolder.getBean(BlockRuleService.class);
            String keyword = blockRuleService.firstMatchedKeyword(domain);
            if (keyword == null) {
                return false;
            }
            System.out.printf("[BLOCK:%s:%d] %s -> %s domain=%s keyword=%s%n",
                    protocol, listenPort, clientIp, targetIp, domain, keyword);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static void cleanup(int chanId) {
        tlsParsers.remove(chanId);
        inspectedBytes.remove(chanId);
        stateLastSeen.remove(chanId);
        SSDetector.cleanup(chanId);
    }

    private static boolean touchState(int chanId) {
        long now = System.currentTimeMillis();
        if (stateLastSeen.replace(chanId, now) != null) {
            return true;
        }

        if (stateLastSeen.size() >= MAX_STATE_ENTRIES) {
            cleanupExpired(now);
            if (stateLastSeen.size() >= MAX_STATE_ENTRIES) {
                return false;
            }
        }

        Long previous = stateLastSeen.putIfAbsent(chanId, now);
        return previous == null || stateLastSeen.replace(chanId, previous, now);
    }

    private static void cleanupExpired(long now) {
        stateLastSeen.entrySet().removeIf(entry -> {
            if (now - entry.getValue() <= STATE_TTL_MS) {
                return false;
            }
            int chanId = entry.getKey();
            tlsParsers.remove(chanId);
            inspectedBytes.remove(chanId);
            SSDetector.cleanup(chanId);
            return true;
        });
    }
}
