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

import java.util.ArrayList;
import java.util.List;

@Component
public class Socks5Server {

    private final AuthConfigService authConfigService;

    public Socks5Server(AuthConfigService authConfigService) {
        this.authConfigService = authConfigService;
    }

    public void start() throws InterruptedException {
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        List<Channel> boundChannels = new ArrayList<>();
        List<AuthConfigService.InboundConfig> inbounds = authConfigService.currentInbounds().stream()
                .filter(AuthConfigService.InboundConfig::enabled)
                .toList();

        try {
            if (inbounds.isEmpty()) {
                System.out.println("[SOCKS5] no enabled inbound configured");
                return;
            }

            ServerBootstrap bootstrap = new ServerBootstrap();
            bootstrap.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.SO_KEEPALIVE, false)
                    .childOption(ChannelOption.TCP_NODELAY, true);

            for (AuthConfigService.InboundConfig inbound : inbounds) {
                final int listenPort = inbound.port();
                ServerBootstrap portBootstrap = bootstrap.clone();
                portBootstrap.childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(
                                Socks5Handler.HANDSHAKE_IDLE_HANDLER,
                                Socks5Handler.newHandshakeIdleHandler());
                        ch.pipeline().addLast(new Socks5Handler(inbound));
                    }
                });

                Channel channel = portBootstrap.bind(listenPort).sync().channel();
                boundChannels.add(channel);
                System.out.println("[SOCKS5] listening on port " + listenPort + " (" + inbound.nickname() + ")");
            }

            for (Channel channel : boundChannels) {
                channel.closeFuture().sync();
            }
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }
}
