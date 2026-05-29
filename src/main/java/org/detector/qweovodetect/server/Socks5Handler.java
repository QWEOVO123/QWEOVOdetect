package org.detector.qweovodetect.server;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.codec.haproxy.*;
import io.netty.handler.codec.haproxy.HAProxyMessage;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import org.detector.qweovodetect.dpi.SpringContextHolder;
import org.detector.qweovodetect.stats.AuthConfigService;
import org.detector.qweovodetect.stats.BlockRuleService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

public class Socks5Handler extends ChannelInboundHandlerAdapter {

    private static final AtomicInteger idGen = new AtomicInteger(0);
    private static final int HANDSHAKE_IDLE_TIMEOUT_SECONDS = 60;
    public static final String HANDSHAKE_IDLE_HANDLER = "handshakeIdle";
    private static final PasswordEncoder SOCKS_PASSWORD_ENCODER = new BCryptPasswordEncoder();
    private final int listenPort;
    private final AuthConfigService.InboundConfig inbound;
    private String realClientIp = null;

    public Socks5Handler(AuthConfigService.InboundConfig inbound) {
        this.inbound = inbound;
        this.listenPort = inbound.port();
    }

    private enum Stage {
        PROXY_PROTOCOL,
        HANDSHAKE,
        AUTH,
        REQUEST,
        RELAY
    }

    private Stage stage = Stage.PROXY_PROTOCOL;

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {

        ByteBuf buf = (ByteBuf) msg;

        try {

            switch (stage) {
                case PROXY_PROTOCOL -> handleProxyProtocol(ctx, buf);
                case HANDSHAKE -> handleHandshake(ctx, buf);
                case AUTH -> handleAuth(ctx, buf);
                case REQUEST -> handleRequest(ctx, buf);
                case RELAY -> ctx.fireChannelRead(buf.retain());
            }

        } finally {
            buf.release();
        }
    }

    private void handleProxyProtocol(ChannelHandlerContext ctx, ByteBuf buf) {
        // 检查 Proxy Protocol V2 或 V1
        // V2 以 0x0D 0x0A 0x0D 0x0A 0x00 0x0D 0x0A 0x51 0x55 0x49 0x54 0x0A 开头
        // V1 以 "PROXY " 开头

        byte[] readable = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), readable);
        String head = new String(readable, 0, Math.min(readable.length, 128));

        if (head.startsWith("PROXY ")) {
            // Proxy Protocol V1: PROXY TCP4 1.2.3.4 5.6.7.8 12345 1080\r\n
            int end = head.indexOf("\r\n");
            if (end == -1) {
                // 数据不完整，等下一包
                return;
            }
            String line = head.substring(0, end);
            String[] parts = line.split(" ");
            if (parts.length >= 6) {
                realClientIp = parts[2];
                System.out.println("[Proxy Protocol] 真实客户端: " + realClientIp);
            }
            buf.skipBytes(end + 2); // 跳过 PROXY 行
            stage = Stage.HANDSHAKE;

            // 如果 buf 还有剩余数据，继续解析握手
            if (buf.readableBytes() > 0) {
                handleHandshake(ctx, buf);
            }
        } else if (readable.length >= 16 && readable[0] == 0x0D && readable[1] == 0x0A
                && readable[2] == 0x0D && readable[3] == 0x0A) {
            // Proxy Protocol V2，用 Netty 内置解码器
            // 简单处理：跳过 V2 header（12 + addrLen）
            if (buf.readableBytes() < 16) return;
            int addrLen = ((buf.getByte(14) & 0xFF) << 8) | (buf.getByte(15) & 0xFF);
            int totalLen = 16 + addrLen;
            if (buf.readableBytes() < totalLen) return;

            // 解析 IPv4 源地址
            if (buf.getByte(13) == 0x11 && addrLen >= 12) { // TCP over IPv4
                realClientIp = String.format("%d.%d.%d.%d",
                        buf.getByte(16) & 0xFF, buf.getByte(17) & 0xFF,
                        buf.getByte(18) & 0xFF, buf.getByte(19) & 0xFF);
                System.out.println("[Proxy Protocol V2] 真实客户端: " + realClientIp);
            }
            buf.skipBytes(totalLen);
            stage = Stage.HANDSHAKE;

            if (buf.readableBytes() > 0) {
                handleHandshake(ctx, buf);
            }
        } else {
            // 没有 Proxy Protocol，直接握手
            realClientIp = ((InetSocketAddress) ctx.channel().remoteAddress()).getHostString();
            stage = Stage.HANDSHAKE;
            handleHandshake(ctx, buf);
        }
    }

    private String getClientIp(ChannelHandlerContext ctx) {
        if (realClientIp != null) return realClientIp;
        return ((InetSocketAddress) ctx.channel().remoteAddress()).getHostString();
    }

    private void handleHandshake(ChannelHandlerContext ctx, ByteBuf buf) {
        if (buf.readableBytes() < 3) {
            ctx.close();
            return;
        }

        byte ver = buf.readByte();
        int nmethods = buf.readByte() & 0xFF;

        if (ver != 0x05 || nmethods < 1 || buf.readableBytes() < nmethods) {
            ctx.close();
            return;
        }

        boolean supportsNoAuth = false;
        boolean supportsPassword = false;
        for (int i = 0; i < nmethods; i++) {
            byte method = buf.readByte();
            if (method == 0x00) {
                supportsNoAuth = true;
            } else if (method == 0x02) {
                supportsPassword = true;
            }
        }

        if (inbound.authEnabled()) {
            if (!supportsPassword) {
                ctx.writeAndFlush(Unpooled.wrappedBuffer(new byte[]{0x05, (byte) 0xff}))
                        .addListener(ChannelFutureListener.CLOSE);
                return;
            }
            ctx.writeAndFlush(Unpooled.wrappedBuffer(new byte[]{0x05, 0x02}));
            stage = Stage.AUTH;
            return;
        }

        if (!supportsNoAuth) {
            ctx.writeAndFlush(Unpooled.wrappedBuffer(new byte[]{0x05, (byte) 0xff}))
                    .addListener(ChannelFutureListener.CLOSE);
            return;
        }

        ctx.writeAndFlush(Unpooled.wrappedBuffer(new byte[]{0x05, 0x00}));
        stage = Stage.REQUEST;
    }

    private void handleAuth(ChannelHandlerContext ctx, ByteBuf buf) {
        if (buf.readableBytes() < 2) {
            ctx.close();
            return;
        }

        byte ver = buf.readByte();
        int usernameLength = buf.readByte() & 0xff;
        if (ver != 0x01 || buf.readableBytes() < usernameLength + 1) {
            ctx.close();
            return;
        }

        byte[] usernameBytes = new byte[usernameLength];
        buf.readBytes(usernameBytes);
        int passwordLength = buf.readByte() & 0xff;
        if (buf.readableBytes() < passwordLength) {
            ctx.close();
            return;
        }

        byte[] passwordBytes = new byte[passwordLength];
        buf.readBytes(passwordBytes);
        String username = new String(usernameBytes, StandardCharsets.UTF_8);
        String password = new String(passwordBytes, StandardCharsets.UTF_8);

        boolean ok = inbound.username().equals(username)
                && SOCKS_PASSWORD_ENCODER.matches(password, inbound.passwordHash());
        if (!ok) {
            ctx.writeAndFlush(Unpooled.wrappedBuffer(new byte[]{0x01, 0x01}))
                    .addListener(ChannelFutureListener.CLOSE);
            return;
        }

        ctx.writeAndFlush(Unpooled.wrappedBuffer(new byte[]{0x01, 0x00}));
        stage = Stage.REQUEST;
    }

    private void handleRequest(ChannelHandlerContext ctx, ByteBuf buf) {
        if (buf.readableBytes() < 4) {
            ctx.close();
            return;
        }

        buf.skipBytes(1);
        byte cmd = buf.readByte();
        buf.skipBytes(1);

        if (cmd == 0x03) {
            handleUdpAssociate(ctx, buf);
            return;
        }

        if (cmd != 0x01) {
            sendReply(ctx, (byte) 0x07);
            return;
        }

        String host;
        int port;

        byte atyp = buf.readByte();
        switch (atyp) {
            case 0x01 -> {
                if (buf.readableBytes() < 6) { ctx.close(); return; }
                host = String.format("%d.%d.%d.%d",
                        buf.readByte() & 0xFF, buf.readByte() & 0xFF,
                        buf.readByte() & 0xFF, buf.readByte() & 0xFF);
                port = buf.readUnsignedShort();
            }
            case 0x03 -> {
                if (buf.readableBytes() < 1) { ctx.close(); return; }
                int domainLen = buf.readByte() & 0xFF;
                if (buf.readableBytes() < domainLen + 2) { ctx.close(); return; }
                byte[] domainBytes = new byte[domainLen];
                buf.readBytes(domainBytes);
                host = new String(domainBytes);
                port = buf.readUnsignedShort();
            }
            case 0x04 -> {
                if (buf.readableBytes() < 18) { ctx.close(); return; }
                byte[] ipv6 = new byte[16];
                buf.readBytes(ipv6);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 16; i += 2) {
                    if (i > 0) sb.append(":");
                    sb.append(String.format("%x%x", ipv6[i] & 0xFF, ipv6[i + 1] & 0xFF));
                }
                host = sb.toString();
                port = buf.readUnsignedShort();
            }
            default -> {
                sendReply(ctx, (byte) 0x08);
                return;
            }
        }

        String clientIp = getClientIp(ctx);
        int chanId = idGen.incrementAndGet();
        System.out.println("[CONNECT:" + listenPort + "] " + clientIp + " -> " + host + ":" + port);
        connectAndRelay(ctx, host, port, clientIp, chanId);
    }

    private void handleUdpAssociate(ChannelHandlerContext ctx, ByteBuf buf) {
        String clientIp = getClientIp(ctx);

        if (buf.readableBytes() < 1) { sendReply(ctx, (byte) 0x01); return; }
        byte atyp = buf.readByte();
        switch (atyp) {
            case 0x01 -> { if (buf.readableBytes() < 6) { sendReply(ctx, (byte) 0x01); return; } buf.skipBytes(6); }
            case 0x03 -> {
                if (buf.readableBytes() < 1) { sendReply(ctx, (byte) 0x01); return; }
                int len = buf.readByte() & 0xFF;
                if (buf.readableBytes() < len + 2) { sendReply(ctx, (byte) 0x01); return; }
                buf.skipBytes(len + 2);
            }
            case 0x04 -> { if (buf.readableBytes() < 18) { sendReply(ctx, (byte) 0x01); return; } buf.skipBytes(18); }
            default -> { sendReply(ctx, (byte) 0x08); return; }
        }

        System.out.println("[UDP:" + listenPort + "] " + clientIp + " requested UDP relay");

        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(ctx.channel().eventLoop())
                .channel(NioDatagramChannel.class)
                .handler(new ChannelInitializer<NioDatagramChannel>() {
                    @Override
                    protected void initChannel(NioDatagramChannel ch) {
                        ch.pipeline().addLast(new UdpRelayHandler(ctx.channel(), clientIp, listenPort));
                    }
                });

        bootstrap.bind(0).addListener((ChannelFutureListener) f -> {
            if (!f.isSuccess()) {
                sendReply(ctx, (byte) 0x01);
                ctx.close();
            }
        });
    }

    private void connectAndRelay(ChannelHandlerContext ctx, String host, int port, String clientIp, int chanId) {
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(ctx.channel().eventLoop())
                .channel(ctx.channel().getClass())
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10_000)
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.SO_KEEPALIVE, false)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(new IdleStateHandler(
                                RelayHandler.IDLE_TIMEOUT_SECONDS,
                                RelayHandler.IDLE_TIMEOUT_SECONDS,
                                0));
                        ch.pipeline().addLast(new RelayHandler(ctx.channel(), clientIp, listenPort, 1, chanId, host));
                    }
                });

        ChannelFuture future = bootstrap.connect(host, port);

        future.addListener((ChannelFutureListener) f -> {
            if (f.isSuccess()) {
                String targetAddr = resolveRemoteAddress(f.channel(), host);
                if (isTargetIpBlocked(targetAddr)) {
                    System.out.printf("[BLOCK:TARGET_IP:%d] %s -> %s:%d%n", listenPort, clientIp, targetAddr, port);
                    f.channel().close();
                    sendReply(ctx, (byte) 0x02);
                    ctx.close();
                    return;
                }
                sendReply(ctx, (byte) 0x00);
                ctx.pipeline().remove(Socks5Handler.this);
                if (ctx.pipeline().get(HANDSHAKE_IDLE_HANDLER) != null) {
                    ctx.pipeline().remove(HANDSHAKE_IDLE_HANDLER);
                }
                ctx.pipeline().addLast(new IdleStateHandler(
                        RelayHandler.IDLE_TIMEOUT_SECONDS,
                        RelayHandler.IDLE_TIMEOUT_SECONDS,
                        0));
                ctx.pipeline().addLast(new RelayHandler(f.channel(), clientIp, listenPort, 0, chanId, targetAddr));
                stage = Stage.RELAY;
            } else {
                System.out.println("[CONNECT] 连接失败: " + host + ":" + port);
                sendReply(ctx, (byte) 0x04);
                ctx.close();
            }
        });
    }

    private boolean isTargetIpBlocked(String targetIp) {
        try {
            BlockRuleService blockRuleService = SpringContextHolder.getBean(BlockRuleService.class);
            return blockRuleService != null && blockRuleService.shouldBlockTargetIp(targetIp);
        } catch (Exception e) {
            return false;
        }
    }

    private String resolveRemoteAddress(Channel channel, String fallback) {
        if (channel.remoteAddress() instanceof InetSocketAddress remote) {
            if (remote.getAddress() != null) {
                return remote.getAddress().getHostAddress();
            }
            return remote.getHostString();
        }
        return fallback;
    }

    private void sendReply(ChannelHandlerContext ctx, byte code) {
        byte[] reply = { 0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        ctx.writeAndFlush(Unpooled.wrappedBuffer(reply));
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ctx.close();
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof IdleStateEvent && stage != Stage.RELAY) {
            ctx.close();
            return;
        }
        super.userEventTriggered(ctx, evt);
    }

    public static IdleStateHandler newHandshakeIdleHandler() {
        return new IdleStateHandler(HANDSHAKE_IDLE_TIMEOUT_SECONDS, 0, 0);
    }
}
