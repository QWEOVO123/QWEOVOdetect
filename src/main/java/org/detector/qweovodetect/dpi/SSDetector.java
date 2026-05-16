package org.detector.qweovodetect.dpi;

import org.detector.qweovodetect.stats.StatsService;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SSDetector {

    private static final float MIN_POPCOUNT = 3.4f;
    private static final float MAX_POPCOUNT = 4.6f;
    private static final float MAX_PRINTABLE_RATIO = 35.0f;
    private static final int MIN_PACKET_SIZE = 20;
    private static final int MAX_DETECT_PACKETS = 3;

    private static final byte[] SSH_BANNER = "SSH-".getBytes();
    private static final byte[] MYSQL_BANNER = {0x4a, 0x00, 0x00, 0x00, 0x0a};

    private static final Map<Integer, Integer> detectCountMap = new ConcurrentHashMap<>();
    private static final Map<Integer, Boolean> detectedChannels = new ConcurrentHashMap<>();

    public static boolean detect(byte[] data, String clientIp, String targetIp, int chanId) {
        if (data == null || data.length < MIN_PACKET_SIZE) return false;

        if (detectedChannels.containsKey(chanId)) return false;

        int count = detectCountMap.merge(chanId, 1, Integer::sum);
        if (count > MAX_DETECT_PACKETS) return false;

        if (isTls(data) || isHttp(data)) return false;
        if (isKnownProtocol(data)) return false;

        if (isLikelyEncryptedTunnel(data)) {
            detectedChannels.put(chanId, true);

            float avgPop = calcAvgPopcount(data);
            float printableRatio = calcPrintableRatio(data);

            System.out.printf("[加密隧道检测] %s -> %s 疑似加密隧道 (熵值=%.2f, ASCII比例=%.1f%%)%n",
                    clientIp, targetIp, avgPop, printableRatio);

            System.out.print("[异常数据流] ");
            for (int i = 0; i < Math.min(16, data.length); i++) {
                System.out.printf("%02x ", data[i] & 0xFF);
            }
            System.out.println();

            // 每次检测到立刻入库
            new Thread(() -> {
                try {
                    StatsService statsService = SpringContextHolder.getBean(StatsService.class);
                    if (statsService != null) {
                        statsService.saveSs(clientIp, targetIp);
                    }
                } catch (Exception ignored) {}
            }).start();

            // 追踪高危
            if (SsDetectionTracker.hit(targetIp, clientIp)) {
                System.out.printf("[高危告警] 目标 %s 3分钟内触发%d次！%n",
                        targetIp, SsDetectionTracker.getCount(targetIp));
            }

            return true;
        }
        return false;
    }

    private static boolean isLikelyEncryptedTunnel(byte[] data) {
        float avgPop = calcAvgPopcount(data);
        float printableRatio = calcPrintableRatio(data);

        return avgPop >= MIN_POPCOUNT
                && avgPop <= MAX_POPCOUNT
                && printableRatio <= MAX_PRINTABLE_RATIO
                && isUniformDistribution(data)
                && data[0] != 0x00
                && !hasProtocolStructure(data)
                && !isKnownProtocol(data);
    }

    private static int popcountByte(byte b) {
        int count = 0;
        int val = b & 0xFF;
        while (val != 0) {
            count += val & 1;
            val >>= 1;
        }
        return count;
    }

    private static float calcAvgPopcount(byte[] data) {
        int total = 0;
        for (byte b : data) total += popcountByte(b);
        return (float) total / data.length;
    }

    private static boolean isPrintableAscii(byte b) {
        return (b & 0xFF) >= 0x20 && (b & 0xFF) <= 0x7E;
    }

    private static float calcPrintableRatio(byte[] data) {
        int count = 0;
        for (byte b : data) if (isPrintableAscii(b)) count++;
        return (float) count / data.length * 100;
    }

    private static boolean isUniformDistribution(byte[] data) {
        if (data.length < 20) return false;
        int[] counter = new int[256];
        for (byte b : data) counter[b & 0xFF]++;
        int unique = 0;
        for (int c : counter) if (c > 0) unique++;
        return unique >= 15 && (float) unique / data.length > 0.3f;
    }

    private static boolean hasProtocolStructure(byte[] data) {
        if (data.length < 4) return false;
        int same = 0;
        for (int i = 1; i < 4; i++) if (data[i] == data[0]) same++;
        if (same >= 2) return true;
        if ((data[1] & 0xFF) == (data[0] & 0xFF) + 1
                && (data[2] & 0xFF) == (data[1] & 0xFF) + 1) return true;
        return false;
    }

    private static boolean isKnownProtocol(byte[] data) {
        if (data.length < 5) return false;
        if (data.length >= 4 && startsWith(data, SSH_BANNER)) return true;
        if (data.length >= 3 && data[0] == 0x03 && data[1] == 0x00) return true;
        if (data.length >= 5 && startsWith(data, MYSQL_BANNER)) return true;
        if (data.length >= 8 && data[0] == 0x12 && data[1] == 0x01) return true;
        if (data.length >= 8 && data[0] == 0x00 && data[4] == 0x00) return true;
        return false;
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++)
            if (data[i] != prefix[i]) return false;
        return true;
    }

    private static boolean isTls(byte[] data) {
        if (data.length < 3) return false;
        return (data[0] >= 0x14 && data[0] <= 0x17)
                && data[1] == 0x03
                && (data[2] & 0xFF) >= 0x00 && (data[2] & 0xFF) <= 0x04;
    }

    private static boolean isHttp(byte[] data) {
        if (data.length < 4) return false;
        String s = new String(data, 0, Math.min(data.length, 6)).toUpperCase();
        return s.startsWith("GET ") || s.startsWith("PUT ") || s.startsWith("POST") || s.startsWith("HEAD");
    }

    public static void cleanup(int chanId) {
        detectCountMap.remove(chanId);
        detectedChannels.remove(chanId);
    }
}