package org.detector.qweovodetect.server;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.timeout.IdleStateEvent;
import org.detector.qweovodetect.dpi.DpiConnectionRegistry;
import org.detector.qweovodetect.dpi.DpiModeService;
import org.detector.qweovodetect.dpi.DpiTaskExecutor;
import org.detector.qweovodetect.dpi.QuicSniDpiEngine;
import org.detector.qweovodetect.dpi.SpringContextHolder;
import org.detector.qweovodetect.dpi.TemporaryTargetBlocklist;
import org.detector.qweovodetect.stats.BlockRuleService;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class UdpRelayHandler extends SimpleChannelInboundHandler<DatagramPacket> {

    private final Channel tcpChannel;
    private final String clientIp;
    private final int listenPort;
    private final InetAddress expectedClientAddress;
    private final Set<InetSocketAddress> remoteSenders = ConcurrentHashMap.newKeySet();
    private InetSocketAddress clientSender;

    public UdpRelayHandler(Channel tcpChannel, String clientIp, int listenPort) {
        this.tcpChannel = tcpChannel;
        this.clientIp = clientIp;
        this.listenPort = listenPort;
        this.expectedClientAddress = tcpChannel.remoteAddress() instanceof InetSocketAddress remote
                ? remote.getAddress()
                : null;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        registerUdpRelay(ctx.channel());
        tcpChannel.closeFuture().addListener((ChannelFutureListener) ignored -> ctx.channel().close());

        InetSocketAddress udpLocal = (InetSocketAddress) ctx.channel().localAddress();
        InetAddress bindAddress = selectReplyAddress(udpLocal);
        ByteBuf reply = Unpooled.buffer();

        reply.writeByte(0x05);
        reply.writeByte(0x00);
        reply.writeByte(0x00);
        writeAddress(reply, bindAddress);
        reply.writeShort(udpLocal.getPort());

        tcpChannel.writeAndFlush(reply);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
        if (isClientPacket(packet)) {
            relayClientPacket(ctx, packet);
            return;
        }

        relayRemotePacket(ctx, packet);
    }

    private boolean isClientPacket(DatagramPacket packet) {
        if (remoteSenders.contains(packet.sender())) {
            return false;
        }
        if (clientSender == null) {
            return true;
        }
        return clientSender.equals(packet.sender()) || sameAddress(expectedClientAddress, packet.sender().getAddress());
    }

    private void relayClientPacket(ChannelHandlerContext ctx, DatagramPacket packet) {
        ByteBuf content = packet.content();
        if (content.readableBytes() < 4) {
            System.out.printf("[UDP:%d] drop short client packet from %s (%d bytes)%n",
                    listenPort, packet.sender(), content.readableBytes());
            return;
        }

        content.skipBytes(2);
        byte frag = content.readByte();
        if (frag != 0x00) {
            System.out.printf("[UDP:%d] drop fragmented packet from %s frag=%d%n",
                    listenPort, packet.sender(), frag & 0xff);
            return;
        }

        Target target = readTarget(content, content.readByte());
        if (target == null) {
            System.out.printf("[UDP:%d] drop malformed client packet from %s%n",
                    listenPort, packet.sender());
            return;
        }

        clientSender = packet.sender();

        if (isTargetIpBlocked(target.host())) {
            System.out.printf("[UDP:%d] drop blocked target IP %s -> %s:%d (%d bytes)%n",
                    listenPort, clientIp, target.host(), target.port(), content.readableBytes());
            return;
        }
        if (isTemporarilyBlocked(target)) {
            System.out.printf("[UDP:%d] drop temporary blocked target %s -> %s:%d (%d bytes)%n",
                    listenPort, clientIp, target.host(), target.port(), content.readableBytes());
            return;
        }

        ByteBuf payload = content.retainedSlice();
        int payloadLength = payload.readableBytes();
        boolean submitted = false;
        try {
            if (isAsyncDpi()) {
                inspectQuicAsync(payload, target);
            } else if (QuicSniDpiEngine.inspect(payload, clientIp, listenPort, target.host(), target.port())) {
                System.out.printf("[UDP:%d] drop blocked QUIC %s -> %s:%d (%d bytes)%n",
                        listenPort, clientIp, target.host(), target.port(), payloadLength);
                return;
            }
            InetSocketAddress recipient = new InetSocketAddress(target.host(), target.port());
            remoteSenders.add(recipient);
            ctx.writeAndFlush(new DatagramPacket(payload, recipient))
                    .addListener((ChannelFutureListener) future -> {
                        if (!future.isSuccess()) {
                            System.out.printf("[UDP:%d] send failed %s -> %s:%d - %s%n",
                                    listenPort,
                                    clientIp,
                                    target.host(),
                                    target.port(),
                                    describe(future.cause()));
                        }
                    });
            submitted = true;
        } finally {
            if (!submitted) {
                payload.release();
            }
        }

    }

    private boolean isAsyncDpi() {
        try {
            DpiModeService dpiModeService = SpringContextHolder.getBean(DpiModeService.class);
            return dpiModeService != null && dpiModeService.isAsync();
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTemporarilyBlocked(Target target) {
        try {
            TemporaryTargetBlocklist blocklist = SpringContextHolder.getBean(TemporaryTargetBlocklist.class);
            return blocklist != null && blocklist.isBlocked(clientIp, target.host(), target.port());
        } catch (Exception e) {
            return false;
        }
    }

    private void inspectQuicAsync(ByteBuf payload, Target target) {
        int len = payload.readableBytes();
        if (len < 1200 || len > 65535) {
            return;
        }

        byte[] packet = new byte[len];
        payload.getBytes(payload.readerIndex(), packet);
        DpiTaskExecutor.executeDpiBestEffort(() -> {
            if (!QuicSniDpiEngine.inspect(packet, clientIp, listenPort, target.host(), target.port())) {
                return;
            }
            try {
                TemporaryTargetBlocklist blocklist = SpringContextHolder.getBean(TemporaryTargetBlocklist.class);
                if (blocklist != null) {
                    blocklist.block(clientIp, target.host(), target.port());
                }
            } catch (Exception ignored) {
            }
        });
    }

    private boolean isTargetIpBlocked(String host) {
        try {
            InetAddress address = InetAddress.getByName(host);
            BlockRuleService blockRuleService = SpringContextHolder.getBean(BlockRuleService.class);
            return blockRuleService != null && blockRuleService.shouldBlockTargetIp(address.getHostAddress());
        } catch (Exception e) {
            return false;
        }
    }

    private void relayRemotePacket(ChannelHandlerContext ctx, DatagramPacket packet) {
        InetSocketAddress destination = clientSender;
        if (destination == null) {
            System.out.printf("[UDP:%d] drop remote packet from %s before client sender is known (%d bytes)%n",
                    listenPort, packet.sender(), packet.content().readableBytes());
            return;
        }

        ByteBuf wrapped = Unpooled.buffer(32 + packet.content().readableBytes());
        wrapped.writeShort(0);
        wrapped.writeByte(0);
        writeAddress(wrapped, packet.sender().getAddress());
        wrapped.writeShort(packet.sender().getPort());
        wrapped.writeBytes(packet.content(), packet.content().readerIndex(), packet.content().readableBytes());

        boolean submitted = false;
        try {
            ctx.writeAndFlush(new DatagramPacket(wrapped, destination))
                    .addListener((ChannelFutureListener) future -> {
                        if (!future.isSuccess()) {
                            System.out.printf("[UDP:%d] reply failed %s -> %s - %s%n",
                                    listenPort,
                                    packet.sender(),
                                    destination,
                                    describe(future.cause()));
                        }
                    });
            submitted = true;
        } finally {
            if (!submitted) {
                wrapped.release();
            }
        }

    }

    private static String describe(Throwable cause) {
        if (cause == null) {
            return "unknown";
        }
        return cause.getClass().getSimpleName() + ": " + cause.getMessage();
    }

    private Target readTarget(ByteBuf content, byte atyp) {
        return switch (atyp) {
            case 0x01 -> readIpv4Target(content);
            case 0x03 -> readDomainTarget(content);
            case 0x04 -> readIpv6Target(content);
            default -> null;
        };
    }

    private Target readIpv4Target(ByteBuf content) {
        if (content.readableBytes() < 6) {
            return null;
        }

        byte[] address = new byte[4];
        content.readBytes(address);
        String host = String.format("%d.%d.%d.%d",
                address[0] & 0xFF, address[1] & 0xFF,
                address[2] & 0xFF, address[3] & 0xFF);

        return new Target(host, content.readUnsignedShort());
    }

    private Target readDomainTarget(ByteBuf content) {
        if (content.readableBytes() < 1) {
            return null;
        }

        int domainLen = content.readUnsignedByte();
        if (content.readableBytes() < domainLen + 2) {
            return null;
        }

        byte[] domainBytes = new byte[domainLen];
        content.readBytes(domainBytes);

        return new Target(new String(domainBytes, StandardCharsets.US_ASCII), content.readUnsignedShort());
    }

    private Target readIpv6Target(ByteBuf content) {
        if (content.readableBytes() < 18) {
            return null;
        }

        byte[] address = new byte[16];
        content.readBytes(address);
        try {
            return new Target(InetAddress.getByAddress(address).getHostAddress(), content.readUnsignedShort());
        } catch (Exception e) {
            return null;
        }
    }

    private InetAddress selectReplyAddress(InetSocketAddress udpLocal) {
        InetAddress udpAddress = udpLocal.getAddress();
        if (udpAddress != null && !udpAddress.isAnyLocalAddress()) {
            return udpAddress;
        }

        if (tcpChannel.localAddress() instanceof InetSocketAddress tcpLocal
                && tcpLocal.getAddress() != null
                && !tcpLocal.getAddress().isAnyLocalAddress()) {
            return tcpLocal.getAddress();
        }

        return wildcardIpv4Address();
    }

    private static boolean sameAddress(InetAddress left, InetAddress right) {
        return left != null && right != null && left.equals(right);
    }

    private static InetAddress wildcardIpv4Address() {
        try {
            return InetAddress.getByAddress(new byte[]{0, 0, 0, 0});
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Unable to create IPv4 wildcard address", e);
        }
    }

    private static void writeAddress(ByteBuf out, InetAddress address) {
        if (address instanceof Inet4Address) {
            out.writeByte(0x01);
            out.writeBytes(address.getAddress());
            return;
        }

        if (address instanceof Inet6Address) {
            out.writeByte(0x04);
            out.writeBytes(address.getAddress());
            return;
        }

        out.writeByte(0x01);
        out.writeInt(0);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        unregisterUdpRelay(ctx.channel());
        tcpChannel.close();
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        unregisterUdpRelay(ctx.channel());
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof IdleStateEvent) {
            ctx.close();
            return;
        }
        super.userEventTriggered(ctx, evt);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }

    private record Target(String host, int port) {
    }

    private void registerUdpRelay(Channel channel) {
        try {
            DpiConnectionRegistry registry = SpringContextHolder.getBean(DpiConnectionRegistry.class);
            if (registry != null) {
                registry.registerUdp(channel);
            }
        } catch (Exception ignored) {
        }
    }

    private void unregisterUdpRelay(Channel channel) {
        try {
            DpiConnectionRegistry registry = SpringContextHolder.getBean(DpiConnectionRegistry.class);
            if (registry != null) {
                registry.unregisterUdp(channel);
            }
        } catch (Exception ignored) {
        }
    }
}
