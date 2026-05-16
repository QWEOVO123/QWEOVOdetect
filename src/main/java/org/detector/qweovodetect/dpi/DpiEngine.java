package org.detector.qweovodetect.dpi;

import io.netty.buffer.ByteBuf;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DpiEngine {

    private static final Map<Integer, TlsSniParser> tlsParsers = new ConcurrentHashMap<>();
    private static final Map<Integer, Integer> inspectedBytes = new ConcurrentHashMap<>();

    //只检测连接前 8KB
    private static final int MAX_INSPECT = 8192;

    public static void inspect(ByteBuf buf,
                               String clientIp,
                               String targetIp,
                               int chanId,
                               int dir) {

        if (dir != 0) return;

        int readableBytes = buf.readableBytes();

        int inspected = inspectedBytes.getOrDefault(chanId, 0);

        if (inspected >= MAX_INSPECT) {
            return;
        }

        int len = Math.min(readableBytes, 1024);

        byte[] data = new byte[len];
        buf.getBytes(buf.readerIndex(), data, 0, len);

        inspectedBytes.merge(chanId, len, Integer::sum);

        HttpHostParser.parse(data, clientIp);
        feedTls(chanId, data, clientIp);
        SSDetector.detect(data, clientIp, targetIp, chanId);
    }

    private static void feedTls(int chanId, byte[] data, String clientIp) {
        tlsParsers
                .computeIfAbsent(chanId, k -> new TlsSniParser())
                .feed(data, clientIp);
    }

    public static void cleanup(int chanId) {
        tlsParsers.remove(chanId);
        inspectedBytes.remove(chanId);
        SSDetector.cleanup(chanId);
    }
}
