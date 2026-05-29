package org.detector.qweovodetect.server;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import org.detector.qweovodetect.stats.AuthConfigService;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class Socks5Server {

    private final AuthConfigService authConfigService;
    private final EventLoopGroup bossGroup = new NioEventLoopGroup(1);
    private final EventLoopGroup workerGroup = new NioEventLoopGroup();
    private final Map<Integer, Channel> boundChannels = new HashMap<>();
    private final Map<Integer, AuthConfigService.InboundConfig> inboundConfigs = new HashMap<>();
    private ServerBootstrap bootstrap;

    public Socks5Server(AuthConfigService authConfigService) {
        this.authConfigService = authConfigService;
    }

    public synchronized void start() {
        if (bootstrap != null) {
            return;
        }

        bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.SO_KEEPALIVE, false)
                .childOption(ChannelOption.TCP_NODELAY, true);

        reload(authConfigService.currentInbounds());
    }

    public synchronized void reload(List<AuthConfigService.InboundConfig> nextInbounds) {
        if (bootstrap == null) {
            start();
            return;
        }

        Map<Integer, AuthConfigService.InboundConfig> nextEnabled = new HashMap<>();
        for (AuthConfigService.InboundConfig inbound : nextInbounds) {
            if (inbound.enabled()) {
                nextEnabled.put(inbound.port(), inbound);
            }
        }

        for (Integer port : List.copyOf(boundChannels.keySet())) {
            if (!nextEnabled.containsKey(port)) {
                closeInbound(port);
            }
        }

        for (AuthConfigService.InboundConfig inbound : nextEnabled.values()) {
            AuthConfigService.InboundConfig current = inboundConfigs.get(inbound.port());
            if (!boundChannels.containsKey(inbound.port())) {
                bindInbound(inbound);
            } else if (!sameRuntimeConfig(current, inbound)) {
                inboundConfigs.put(inbound.port(), inbound);
                System.out.println("[SOCKS5] updated inbound on port " + inbound.port() + " (" + inbound.nickname() + ")");
            }
        }

        if (boundChannels.isEmpty()) {
            System.out.println("[SOCKS5] no enabled inbound configured");
        }
    }

    public synchronized void validateReload(List<AuthConfigService.InboundConfig> nextInbounds) {
        for (AuthConfigService.InboundConfig inbound : nextInbounds) {
            if (inbound.enabled() && !boundChannels.containsKey(inbound.port()) && !canBind(inbound.port())) {
                throw new IllegalArgumentException("SOCKS5 入站端口不可用：" + inbound.port());
            }
        }
    }

    private void bindInbound(AuthConfigService.InboundConfig inbound) {
        ServerBootstrap portBootstrap = bootstrap.clone();
        portBootstrap.childHandler(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) {
                AuthConfigService.InboundConfig latest = inboundConfigs.getOrDefault(inbound.port(), inbound);
                ch.pipeline().addLast(
                        Socks5Handler.HANDSHAKE_IDLE_HANDLER,
                        Socks5Handler.newHandshakeIdleHandler());
                ch.pipeline().addLast(new Socks5Handler(latest));
            }
        });

        try {
            Channel channel = portBootstrap.bind(inbound.port()).sync().channel();
            boundChannels.put(inbound.port(), channel);
            inboundConfigs.put(inbound.port(), inbound);
            System.out.println("[SOCKS5] listening on port " + inbound.port() + " (" + inbound.nickname() + ")");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("绑定 SOCKS5 入站端口被中断：" + inbound.port(), e);
        } catch (Exception e) {
            throw new IllegalArgumentException("绑定 SOCKS5 入站端口失败：" + inbound.port() + "，" + e.getMessage(), e);
        }
    }

    private void closeInbound(int port) {
        Channel channel = boundChannels.remove(port);
        inboundConfigs.remove(port);
        if (channel != null) {
            channel.close();
        }
        System.out.println("[SOCKS5] closed inbound on port " + port);
    }

    private boolean sameRuntimeConfig(AuthConfigService.InboundConfig left, AuthConfigService.InboundConfig right) {
        if (left == null || right == null) {
            return false;
        }
        return left.nickname().equals(right.nickname())
                && left.authEnabled() == right.authEnabled()
                && left.username().equals(right.username())
                && left.passwordHash().equals(right.passwordHash());
    }

    private boolean canBind(int port) {
        ServerBootstrap probe = bootstrap.clone();
        probe.childHandler(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) {
                ch.close();
            }
        });
        try {
            Channel channel = probe.bind(port).sync().channel();
            channel.close().sync();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
