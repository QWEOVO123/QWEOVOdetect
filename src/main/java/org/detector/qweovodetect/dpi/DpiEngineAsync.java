package org.detector.qweovodetect.dpi;

import io.netty.buffer.ByteBuf;

public class DpiEngineAsync {

    public static void inspect(ByteBuf buf,
                               String clientIp,
                               int listenPort,
                               String targetIp,
                               int chanId) {
        inspect(buf, clientIp, listenPort, targetIp, chanId, 0);
    }

    public static void inspect(ByteBuf buf,
                               String clientIp,
                               int listenPort,
                               String targetIp,
                               int chanId,
                               int dir) {
        if (buf == null || !buf.isReadable() || !DpiEngine.shouldInspect(chanId, dir)) {
            return;
        }

        int len = Math.min(buf.readableBytes(), DpiEngine.MAX_CHUNK_INSPECT);
        byte[] copy = new byte[len];
        buf.getBytes(buf.readerIndex(), copy, 0, len);

        DpiTaskExecutor.executeDpi(() -> DpiEngine.inspect(copy, clientIp, listenPort, targetIp, chanId, dir));
    }
}
