package org.detector.qweovodetect.dpi;

import io.netty.buffer.ByteBuf;
import org.detector.qweovodetect.stats.ForensicsService;
import org.detector.qweovodetect.stats.StatsService;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class TrojanDpiEngineAsync {

    private static final byte[] CCS = {20, 3, 3, 0, 1, 1};
    private static final int DIR_UPLOAD = 0;
    private static final int DIR_DOWNLOAD = 1;

    private static final Map<Integer, FlowState> states = new ConcurrentHashMap<>();

    public static void inspect(ByteBuf buf,
                               String clientIp,
                               int listenPort,
                               String targetIp,
                               int chanId,
                               int dir) {
        if (buf == null || !buf.isReadable()) {
            return;
        }

        FlowState state = states.computeIfAbsent(chanId, ignored -> new FlowState());
        TrojanHit hit;
        synchronized (state) {
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

        System.out.printf("[Trojan:%d] %s -> %s matched upload=%d download=%d%n",
                listenPort, clientIp, targetIp, hit.uploadBytes(), hit.downloadBytes());

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

    private static class FlowState {
        private boolean uploading;
        private int uploadCount;
        private boolean downloading;
        private int downloadCount;
        private boolean finished;
    }

    private record TrojanHit(int uploadBytes, int downloadBytes) {
    }
}
