package org.detector.qweovodetect.dpi;

import io.netty.channel.Channel;
import io.netty.channel.socket.SocketChannel;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class DpiConnectionRegistry {

    private final Set<TcpRelay> tcpRelays = ConcurrentHashMap.newKeySet();
    private final Set<Channel> udpRelays = ConcurrentHashMap.newKeySet();

    public TcpRelay registerTcp(Channel first, Channel second) {
        TcpRelay relay = new TcpRelay(first, second);
        tcpRelays.add(relay);
        return relay;
    }

    public void unregisterTcp(TcpRelay relay) {
        if (relay != null) {
            tcpRelays.remove(relay);
        }
    }

    public void registerUdp(Channel channel) {
        if (channel != null) {
            udpRelays.add(channel);
        }
    }

    public void unregisterUdp(Channel channel) {
        if (channel != null) {
            udpRelays.remove(channel);
        }
    }

    public ResetSummary resetAll() {
        int tcpCount = 0;
        for (TcpRelay relay : tcpRelays) {
            closeTcpRelay(relay);
            tcpCount++;
        }
        tcpRelays.clear();

        int udpCount = 0;
        for (Channel channel : udpRelays) {
            closeOnEventLoop(channel);
            udpCount++;
        }
        udpRelays.clear();

        return new ResetSummary(tcpCount, udpCount);
    }

    private void closeTcpRelay(TcpRelay relay) {
        closeTcpChannel(relay.first());
        closeTcpChannel(relay.second());
    }

    private void closeTcpChannel(Channel channel) {
        if (channel == null) {
            return;
        }
        channel.eventLoop().execute(() -> {
            enableRstOnClose(channel);
            if (channel.isOpen()) {
                channel.close();
            }
        });
    }

    private void closeOnEventLoop(Channel channel) {
        if (channel == null) {
            return;
        }
        channel.eventLoop().execute(() -> {
            if (channel.isOpen()) {
                channel.close();
            }
        });
    }

    private static void enableRstOnClose(Channel channel) {
        if (channel instanceof SocketChannel socketChannel) {
            try {
                socketChannel.config().setSoLinger(0);
            } catch (Exception ignored) {
            }
        }
    }

    public record TcpRelay(Channel first, Channel second) {
    }

    public record ResetSummary(int tcpRelays, int udpRelays) {
    }
}
