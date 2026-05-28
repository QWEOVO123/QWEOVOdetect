package org.detector.qweovodetect.dpi;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class SsDetectionTracker {

    private static final Map<String, List<Long>> targetHits = new ConcurrentHashMap<>();
    private static final Map<String, Set<String>> targetClients = new ConcurrentHashMap<>();
    private static final Map<String, Long> alreadyReportedAt = new ConcurrentHashMap<>();

    private static final long WINDOW_MS = 300_000;
    private static final long REPORTED_CACHE_MS = 1_800_000;
    private static final int THRESHOLD = 20;

    public static synchronized boolean hit(String targetAddr, String clientIp) {
        long now = Instant.now().toEpochMilli();
        prune(now);

        Long reportedAt = alreadyReportedAt.get(targetAddr);
        if (reportedAt != null && now - reportedAt <= REPORTED_CACHE_MS) {
            return false;
        }

        targetClients.computeIfAbsent(targetAddr, k -> ConcurrentHashMap.newKeySet()).add(clientIp);

        List<Long> hits = targetHits.computeIfAbsent(targetAddr, k -> new ArrayList<>());
        hits.add(now);
        hits.removeIf(t -> now - t > WINDOW_MS);

        int count = hits.size();
        if (count >= THRESHOLD) {
            alreadyReportedAt.put(targetAddr, now);
            System.out.printf("[楂樺嵄鍒ゅ畾] 鐩爣 %s 鍦?鍒嗛挓鍐呰Е鍙?d娆★紝鍏宠仈瀹㈡埛绔? %s%n",
                    targetAddr, count, targetClients.get(targetAddr));
            return true;
        }

        if (count >= 10 && count % 5 == 0) {
            System.out.printf("[杩借釜涓璢 %s 褰撳墠鍛戒腑娆℃暟: %d/%d%n",
                    targetAddr, count, THRESHOLD);
        }

        return false;
    }

    public static synchronized Set<String> getClients(String targetAddr) {
        return targetClients.getOrDefault(targetAddr, Collections.emptySet());
    }

    public static synchronized int getCount(String targetAddr) {
        List<Long> hits = targetHits.get(targetAddr);
        if (hits == null) return 0;
        long now = Instant.now().toEpochMilli();
        hits.removeIf(t -> now - t > WINDOW_MS);
        if (hits.isEmpty()) {
            targetHits.remove(targetAddr);
            targetClients.remove(targetAddr);
        }
        return hits.size();
    }

    private static void prune(long now) {
        targetHits.entrySet().removeIf(entry -> {
            entry.getValue().removeIf(t -> now - t > WINDOW_MS);
            boolean empty = entry.getValue().isEmpty();
            if (empty) {
                targetClients.remove(entry.getKey());
            }
            return empty;
        });

        alreadyReportedAt.entrySet().removeIf(entry -> now - entry.getValue() > REPORTED_CACHE_MS);
    }

    public static synchronized void reset() {
        targetHits.clear();
        targetClients.clear();
        alreadyReportedAt.clear();
    }
}
