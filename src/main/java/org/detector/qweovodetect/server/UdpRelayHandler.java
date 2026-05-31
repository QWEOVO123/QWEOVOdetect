package org.detector.qweovodetect.server;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.timeout.IdleStateEvent;
import org.detector.qweovodetect.dpi.QuicSniDpiEngine;
import org.detector.qweovodetect.dpi.SpringContextHolder;
import org.detector.qweovodetect.stats.BlockRuleService;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class UdpRelayHandler extends SimpleChannelInboundHandler<DatagramPacket> {

    private final Channel tcpChannel;
    private final String clientIp;
    private final int listenPort;
    private InetSocketAddress clientSender;

    public UdpRelayHandler(Channel tcpChannel, String clientIp, int listenPort) {
        this.tcpChannel = tcpChannel;
        this.clientIp = clientIp;
        this.listenPort = listenPort;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
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
        System.out.println("[UDP:" + listenPort + "] native relay ready " + bindAddress.getHostAddress() + ":" + udpLocal.getPort());
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
        if (clientSender == null) {
            return true;
        }
        return clientSender.equals(packet.sender());
    }

    private void relayClientPacket(ChannelHandlerContext ctx, DatagramPacket packet) {
        ByteBuf content = packet.content();
        if (content.readableBytes() < 4) {
            return;
        }

        content.skipBytes(2);
        byte frag = content.readByte();
        if (frag != 0x00) {
            return;
        }

        Target target = readTarget(content, content.readByte());
        if (target == null) {
            return;
        }

        clientSender = packet.sender();

        if (isTargetIpBlocked(target.host())) {
            System.out.printf("[UDP:%d] drop blocked target IP %s -> %s:%d (%d bytes)%n",
                    listenPort, clientIp, target.host(), target.port(), content.readableBytes());
            return;
        }

        ByteBuf payload = content.retainedSlice();
        boolean submitted = false;
        try {
            if (QuicSniDpiEngine.inspect(payload, clientIp, listenPort, target.host(), target.port())) {
                System.out.printf("[UDP:%d] drop blocked QUIC %s -> %s:%d (%d bytes)%n",
                        listenPort, clientIp, target.host(), target.port(), payload.readableBytes());
                return;
            }
            ctx.writeAndFlush(new DatagramPacket(payload, new InetSocketAddress(target.host(), target.port())));
            submitted = true;
        } finally {
            if (!submitted) {
                payload.release();
            }
        }

        System.out.printf("[UDP:%d] %s -> %s:%d (%d bytes)%n",
                listenPort, clientIp, target.host(), target.port(), payload.readableBytes());
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
            ctx.writeAndFlush(new DatagramPacket(wrapped, destination));
            submitted = true;
        } finally {
            if (!submitted) {
                wrapped.release();
            }
        }
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

        return InetAddress.getLoopbackAddress();
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
        tcpChannel.close();
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof IdleStateEvent) {
            System.out.printf("[UDP:%d] idle timeout %s, closing relay%n", listenPort, clientIp);
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
}
