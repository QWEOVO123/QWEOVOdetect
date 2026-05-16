package org.detector.qweovodetect.server;

import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import org.detector.qweovodetect.dpi.DpiEngineAsync;
import org.detector.qweovodetect.dpi.DpiEngine;
import org.detector.qweovodetect.dpi.TrojanDpiEngineAsync;

public class RelayHandler extends ChannelInboundHandlerAdapter {

    private final Channel relayTarget;
    private final String clientIp;
    private final String targetIp;
    private final int direction;
    private final int chanId;

    public RelayHandler(Channel relayTarget,
                        String clientIp,
                        int direction,
                        int chanId,
                        String targetIp) {

        this.relayTarget = relayTarget;
        this.clientIp = clientIp;
        this.direction = direction;
        this.chanId = chanId;
        this.targetIp = targetIp;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {

        ByteBuf buf = (ByteBuf) msg;

        try {

            // ⭐ DPI 仅客户端方向
            TrojanDpiEngineAsync.inspect(buf, clientIp, targetIp, chanId, direction);
            if (direction == 0) {
                DpiEngineAsync.inspect(buf, clientIp, targetIp, chanId);
            }

            // ⭐ 只 write，不 flush
            relayTarget.write(buf.retain());

            // ⭐⭐⭐ 关键修复：继续读取 socket
            ctx.read();

        } finally {
            buf.release();
        }
    }

    // ⭐ batch flush
    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        relayTarget.flush();
    }

    // ⭐ TCP Backpressure
    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {

        boolean writable = relayTarget.isWritable();
        ctx.channel().config().setAutoRead(writable);

        if (writable) {
            ctx.read(); // ⭐ 恢复读取（关键）
        }

        ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        DpiEngine.cleanup(chanId);
        TrojanDpiEngineAsync.cleanup(chanId);

        if (relayTarget.isActive()) {
            relayTarget.close();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ctx.close();
    }
}
