package org.detector.qweovodetect.server;

import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.timeout.IdleStateEvent;
import org.detector.qweovodetect.dpi.DpiConnectionRegistry;
import org.detector.qweovodetect.dpi.DpiEngine;
import org.detector.qweovodetect.dpi.DpiModeService;
import org.detector.qweovodetect.dpi.DpiTaskExecutor;
import org.detector.qweovodetect.dpi.SpringContextHolder;
import org.detector.qweovodetect.dpi.TemporaryTargetBlocklist;
import org.detector.qweovodetect.dpi.TrojanDpiEngineAsync;

public class RelayHandler extends ChannelInboundHandlerAdapter {

    public static final int IDLE_TIMEOUT_SECONDS = 180;

    private final Channel relayTarget;
    private final String clientIp;
    private final int listenPort;
    private final String targetIp;
    private final int targetPort;
    private final int direction;
    private final int chanId;
    private DpiConnectionRegistry.TcpRelay registeredRelay;

    public RelayHandler(Channel relayTarget,
                        String clientIp,
                        int listenPort,
                        int direction,
                        int chanId,
                        String targetIp,
                        int targetPort) {

        this.relayTarget = relayTarget;
        this.clientIp = clientIp;
        this.listenPort = listenPort;
        this.direction = direction;
        this.chanId = chanId;
        this.targetIp = targetIp;
        this.targetPort = targetPort;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        try {
            DpiConnectionRegistry registry = SpringContextHolder.getBean(DpiConnectionRegistry.class);
            if (registry != null) {
                registeredRelay = registry.registerTcp(ctx.channel(), relayTarget);
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        ByteBuf buf = (ByteBuf) msg;

        try {
            TrojanDpiEngineAsync.inspect(buf, clientIp, listenPort, targetIp, chanId, direction);
            if (direction == 0) {
                if (isTemporarilyBlocked()) {
                    closeBothWithRst(ctx.channel(), relayTarget);
                    return;
                }
                if (isAsyncDpi()) {
                    inspectAsync(ctx, buf);
                } else if (DpiEngine.inspectAndShouldBlock(buf, clientIp, listenPort, targetIp, chanId, direction)) {
                    closeBothWithRst(ctx.channel(), relayTarget);
                    return;
                }
            }

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

            ctx.read();
        } finally {
            buf.release();
        }
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        relayTarget.flush();
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
        boolean writable = relayTarget.isWritable();
        ctx.channel().config().setAutoRead(writable);

        if (writable) {
            ctx.read();
        }

        ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        unregisterRelay();
        DpiEngine.cleanup(chanId);
        TrojanDpiEngineAsync.cleanup(chanId);
        closeBoth(ctx.channel(), relayTarget);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        closeBoth(ctx.channel(), relayTarget);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        unregisterRelay();
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof IdleStateEvent) {
            closeBoth(ctx.channel(), relayTarget);
            return;
        }
        super.userEventTriggered(ctx, evt);
    }

    private boolean isAsyncDpi() {
        try {
            DpiModeService dpiModeService = SpringContextHolder.getBean(DpiModeService.class);
            return dpiModeService != null && dpiModeService.isAsync();
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTemporarilyBlocked() {
        try {
            TemporaryTargetBlocklist blocklist = SpringContextHolder.getBean(TemporaryTargetBlocklist.class);
            return blocklist != null && blocklist.isBlocked(clientIp, targetIp, targetPort);
        } catch (Exception e) {
            return false;
        }
    }

    private void inspectAsync(ChannelHandlerContext ctx, ByteBuf buf) {
        if (!DpiEngine.shouldInspect(chanId, direction)) {
            return;
        }

        int len = Math.min(buf.readableBytes(), DpiEngine.MAX_CHUNK_INSPECT);
        byte[] copy = new byte[len];
        buf.getBytes(buf.readerIndex(), copy, 0, len);

        DpiTaskExecutor.executeDpiBestEffort(() -> {
            if (!DpiEngine.inspectAndShouldBlock(copy, clientIp, listenPort, targetIp, chanId, direction)) {
                return;
            }
            blockTemporarily();
            ctx.channel().eventLoop().execute(() -> closeBothWithRst(ctx.channel(), relayTarget));
        });
    }

    private void blockTemporarily() {
        try {
            TemporaryTargetBlocklist blocklist = SpringContextHolder.getBean(TemporaryTargetBlocklist.class);
            if (blocklist != null) {
                blocklist.block(clientIp, targetIp, targetPort);
            }
        } catch (Exception ignored) {
        }
    }

    private void unregisterRelay() {
        try {
            DpiConnectionRegistry registry = SpringContextHolder.getBean(DpiConnectionRegistry.class);
            if (registry != null) {
                registry.unregisterTcp(registeredRelay);
            }
        } catch (Exception ignored) {
        }
        registeredRelay = null;
    }

    private static void closeBoth(Channel first, Channel second) {
        if (first != null && first.isOpen()) {
            first.close();
        }
        if (second != null && second.isOpen()) {
            second.close();
        }
    }

    private static void closeBothWithRst(Channel first, Channel second) {
        enableRstOnClose(first);
        enableRstOnClose(second);
        closeBoth(first, second);
    }

    private static void enableRstOnClose(Channel channel) {
        if (channel instanceof SocketChannel socketChannel) {
            try {
                socketChannel.config().setSoLinger(0);
            } catch (Exception ignored) {
            }
        }
    }
}
