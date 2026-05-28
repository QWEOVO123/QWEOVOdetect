package org.detector.qweovodetect.dpi;

import io.netty.buffer.ByteBuf;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DpiEngine {

    public static final int MAX_CHUNK_INSPECT = 1024;

    private static final Map<Integer, TlsSniParser> tlsParsers = new ConcurrentHashMap<>();
    private static final Map<Integer, Integer> inspectedBytes = new ConcurrentHashMap<>();

    private static final int MAX_INSPECT = 8192;

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

    public static void inspect(byte[] data,
                               String clientIp,
                               int listenPort,
                               String targetIp,
                               int chanId,
                               int dir) {
        if (data == null || data.length == 0 || !shouldInspect(chanId, dir)) {
            return;
        }

        inspectedBytes.merge(chanId, data.length, Integer::sum);

        HttpHostParser.parse(data, clientIp);
        feedTls(chanId, data, clientIp, listenPort);
        SSDetector.detect(data, clientIp, listenPort, targetIp, chanId);
    }

    public static boolean shouldInspect(int chanId, int dir) {
        if (dir != 0) {
            return false;
        }
        return inspectedBytes.getOrDefault(chanId, 0) < MAX_INSPECT;
    }

    private static void feedTls(int chanId, byte[] data, String clientIp, int listenPort) {
        tlsParsers
                .computeIfAbsent(chanId, k -> new TlsSniParser())
                .feed(data, clientIp, listenPort);
    }

    public static void cleanup(int chanId) {
        tlsParsers.remove(chanId);
        inspectedBytes.remove(chanId);
        SSDetector.cleanup(chanId);
    }
}
