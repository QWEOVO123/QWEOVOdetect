package org.detector.qweovodetect.dpi;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class SsDetectionTracker {

    // 目标地址 -> 触发时间列表
    private static final Map<String, List<Long>> targetHits = new ConcurrentHashMap<>();

    // 目标地址 -> 触发过的客户端IP集合
    private static final Map<String, Set<String>> targetClients = new ConcurrentHashMap<>();

    // 已判定的高危目标
    private static final Set<String> alreadyReported = ConcurrentHashMap.newKeySet();

    // 5分钟窗口
    private static final long WINDOW_MS = 300_000;
    private static final int THRESHOLD = 20;

    /**
     * @return 是否达到高危阈值
     */
    public static synchronized boolean hit(String targetAddr, String clientIp) {
        if (alreadyReported.contains(targetAddr)) {
            return false;
        }

        long now = Instant.now().toEpochMilli();

        targetClients.computeIfAbsent(targetAddr, k -> ConcurrentHashMap.newKeySet()).add(clientIp);

        List<Long> hits = targetHits.computeIfAbsent(targetAddr, k -> new ArrayList<>());
        hits.add(now);
        hits.removeIf(t -> now - t > WINDOW_MS);

        int count = hits.size();
        if (count >= THRESHOLD) {
            alreadyReported.add(targetAddr);
            System.out.printf("[高危判定] 目标 %s 在5分钟内触发%d次，关联客户端: %s%n",
                    targetAddr, count, targetClients.get(targetAddr));
            return true;
        }

        if (count >= 10 && count % 5 == 0) {
            System.out.printf("[追踪中] %s 当前命中次数: %d/%d%n",
                    targetAddr, count, THRESHOLD);
        }

        return false;
    }

    public static Set<String> getClients(String targetAddr) {
        return targetClients.getOrDefault(targetAddr, Collections.emptySet());
    }

    public static int getCount(String targetAddr) {
        List<Long> hits = targetHits.get(targetAddr);
        if (hits == null) return 0;
        long now = Instant.now().toEpochMilli();
        hits.removeIf(t -> now - t > WINDOW_MS);
        return hits.size();
    }

    public static void reset() {
        targetHits.clear();
        targetClients.clear();
        alreadyReported.clear();
    }
}