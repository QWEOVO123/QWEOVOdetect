package org.detector.qweovodetect.server;

import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.handler.timeout.IdleStateEvent;
import org.detector.qweovodetect.dpi.DpiEngineAsync;
import org.detector.qweovodetect.dpi.DpiEngine;
import org.detector.qweovodetect.dpi.TrojanDpiEngineAsync;

public class RelayHandler extends ChannelInboundHandlerAdapter {

    public static final int IDLE_TIMEOUT_SECONDS = 180;

    private final Channel relayTarget;
    private final String clientIp;
    private final int listenPort;
    private final String targetIp;
    private final int direction;
    private final int chanId;

    public RelayHandler(Channel relayTarget,
                        String clientIp,
                        int listenPort,
                        int direction,
                        int chanId,
                        String targetIp) {

        this.relayTarget = relayTarget;
        this.clientIp = clientIp;
        this.listenPort = listenPort;
        this.direction = direction;
        this.chanId = chanId;
        this.targetIp = targetIp;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {

        ByteBuf buf = (ByteBuf) msg;

        try {

            // ⭐ DPI 仅客户端方向
            TrojanDpiEngineAsync.inspect(buf, clientIp, listenPort, targetIp, chanId, direction);
            if (direction == 0) {
                DpiEngineAsync.inspect(buf, clientIp, listenPort, targetIp, chanId);
            }

            // ⭐ 只 write，不 flush
            ByteBuf outbound = buf.retain();
            boolean submitted = false;
            try {
                relayTarget.write(outbound).addListener((ChannelFutureListener) future -> {
                    if (!future.isSuccess()) {
                        closeBoth(ctx.channel(), relayTarget);
                    }
                });
                submitted = true;
            } finally {
                if (!submitted) {
                    outbound.release();
                }
            }

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

        closeBoth(ctx.channel(), relayTarget);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        closeBoth(ctx.channel(), relayTarget);
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof IdleStateEvent) {
            System.out.printf("[RELAY:%d] idle timeout %s -> %s, closing%n", listenPort, clientIp, targetIp);
            closeBoth(ctx.channel(), relayTarget);
            return;
        }
        super.userEventTriggered(ctx, evt);
    }

    private static void closeBoth(Channel first, Channel second) {
        if (first != null && first.isOpen()) {
            first.close();
        }
        if (second != null && second.isOpen()) {
            second.close();
        }
    }
}
