package org.detector.qweovodetect.dpi;

import io.netty.buffer.ByteBuf;
import org.detector.qweovodetect.stats.StatsService;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class TrojanDpiEngineAsync {

    private static final byte[] CCS = {20, 3, 3, 0, 1, 1};
    private static final int DIR_UPLOAD = 0;
    private static final int DIR_DOWNLOAD = 1;

    private static final ExecutorService TROJAN_POOL =
            Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

    private static final ExecutorService DB_POOL =
            Executors.newSingleThreadExecutor();

    private static final Map<Integer, FlowState> states = new ConcurrentHashMap<>();
    private static final Map<Integer, SerialFlowExecutor> flowExecutors = new ConcurrentHashMap<>();

    public static void inspect(ByteBuf buf,
                               String clientIp,
                               String targetIp,
                               int chanId,
                               int dir) {
        if (buf == null || !buf.isReadable()) {
            return;
        }

        byte[] data = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), data);

        flowExecutors
                .computeIfAbsent(chanId, ignored -> new SerialFlowExecutor())
                .execute(() -> inspectBytes(data, clientIp, targetIp, chanId, dir));
    }

    private static void inspectBytes(byte[] data,
                                     String clientIp,
                                     String targetIp,
                                     int chanId,
                                     int dir) {
        if (data.length == 0) {
            return;
        }

        FlowState state = states.computeIfAbsent(chanId, ignored -> new FlowState());
        if (state.finished) {
            return;
        }

        TrojanHit hit;
        if (dir == DIR_UPLOAD) {
            hit = inspectUpload(state, data);
        } else if (dir == DIR_DOWNLOAD) {
            hit = inspectDownload(state, data);
        } else {
            return;
        }

        if (hit == null) {
            return;
        }

        state.finished = true;
        System.out.printf("[Trojan] %s -> %s matched upload=%d download=%d%n",
                clientIp, targetIp, hit.uploadBytes(), hit.downloadBytes());

        DB_POOL.execute(() -> saveTrojan(clientIp, targetIp, hit));
    }

    private static TrojanHit inspectUpload(FlowState state, byte[] data) {
        if (state.uploadCount == 0 && data.length >= CCS.length
                && Arrays.equals(Arrays.copyOf(data, CCS.length), CCS)) {
            state.uploading = true;
        }

        if (state.uploading) {
            state.uploadCount += data.length;
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

    private static TrojanHit inspectDownload(FlowState state, byte[] data) {
        if (state.uploading) {
            state.uploading = false;
            state.downloading = true;
        }

        if (state.downloading) {
            state.downloadCount += data.length;
        }

        return null;
    }

    private static boolean isTrojanSize(int uploadCount, int downloadCount) {
        return uploadCount >= 650 && uploadCount <= 750
                && ((downloadCount >= 170 && downloadCount <= 180)
                || (downloadCount >= 3000 && downloadCount <= 7500));
    }

    private static void saveTrojan(String clientIp, String targetIp, TrojanHit hit) {
        try {
            StatsService statsService = SpringContextHolder.getBean(StatsService.class);
            if (statsService != null) {
                statsService.saveTrojan(clientIp, targetIp, hit.uploadBytes(), hit.downloadBytes());
            }
        } catch (Exception e) {
            System.out.println("[Trojan] save failed: " + e.getMessage());
        }
    }

    public static void cleanup(int chanId) {
        flowExecutors.computeIfPresent(chanId, (ignored, executor) -> {
            executor.execute(() -> states.remove(chanId));
            executor.closeWhenDrained();
            return null;
        });
    }

    private static class SerialFlowExecutor {
        private final Queue<Runnable> tasks = new ArrayDeque<>();
        private boolean running;
        private boolean closeWhenDrained;

        synchronized void execute(Runnable task) {
            if (closeWhenDrained) {
                return;
            }
            tasks.add(task);
            if (!running) {
                running = true;
                TROJAN_POOL.execute(this::runNext);
            }
        }

        synchronized void closeWhenDrained() {
            closeWhenDrained = true;
            if (!running && tasks.isEmpty()) {
                notifyAll();
            }
        }

        private void runNext() {
            while (true) {
                Runnable task;
                synchronized (this) {
                    task = tasks.poll();
                    if (task == null) {
                        running = false;
                        if (closeWhenDrained) {
                            notifyAll();
                        }
                        return;
                    }
                }

                try {
                    task.run();
                } catch (Exception e) {
                    System.out.println("[Trojan] inspect failed: " + e.getMessage());
                }
            }
        }
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
