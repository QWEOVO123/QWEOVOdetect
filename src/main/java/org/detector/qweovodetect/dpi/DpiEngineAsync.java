package org.detector.qweovodetect.dpi;

import io.netty.buffer.ByteBuf;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DpiEngineAsync {

    private static final ExecutorService DPI_POOL =
            Executors.newFixedThreadPool(
                    Runtime.getRuntime().availableProcessors()
            );

    public static void inspect(ByteBuf buf,
                               String clientIp,
                               String targetIp,
                               int chanId) {
        inspect(buf, clientIp, targetIp, chanId, 0);
    }

    public static void inspect(ByteBuf buf,
                               String clientIp,
                               String targetIp,
                               int chanId,
                               int dir) {

        ByteBuf copy = buf.retainedSlice();
        DPI_POOL.execute(() -> {
            try {
                DpiEngine.inspect(copy, clientIp, targetIp, chanId, dir);
            } finally {
                copy.release();
            }
        });
    }
}
