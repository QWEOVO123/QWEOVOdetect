package org.detector.qweovodetect.dpi;

import java.util.Arrays;

/**
 * TLS SNI 解析，支持跨包累积
 */
public class TlsSniParser {

    private final byte[] buffer = new byte[8192];
    private int bufLen = 0;
    private boolean parsed = false;

    /**
     * 喂入数据，如果成功解析 SNI 则返回域名，否则返回 null
     */
    public String feed(byte[] data, String clientIp, int listenPort) {
        if (parsed) return null;
        if (data == null || data.length == 0) return null;

        // 不是 TLS 记录头，且缓冲区为空，丢弃
        if (bufLen == 0 && data.length > 0 && data[0] != 0x16) return null;

        // 累积数据
        if (bufLen + data.length > buffer.length) {
            // 溢出，重置
            bufLen = 0;
            return null;
        }
        System.arraycopy(data, 0, buffer, bufLen, data.length);
        bufLen += data.length;

        // 尝试解析
        String sni = tryParse();
        if (sni != null) {
            parsed = true;
            bufLen = 0;
            System.out.printf("[TLS:%d] %s -> %s%n", listenPort, clientIp, sni);
            //写入数据库
            try {
                org.detector.qweovodetect.stats.StatsService statsService =
                        SpringContextHolder.getBean(org.detector.qweovodetect.stats.StatsService.class);
                if (statsService != null) {
                    statsService.saveSni(clientIp, listenPort, sni);
                }
            } catch (Exception ignored) {}
            try {
                org.detector.qweovodetect.stats.ForensicsService forensicsService =
                        SpringContextHolder.getBean(org.detector.qweovodetect.stats.ForensicsService.class);
                if (forensicsService != null) {
                    forensicsService.recordTls(listenPort, clientIp, sni);
                }
            } catch (Exception ignored) {}
        }
        return sni;
    }

    private String tryParse() {
        int offset = 0;

        while (offset + 5 <= bufLen) {
            if (buffer[offset] != 0x16) {
                offset++;
                continue;
            }

            int tlsVersion = ((buffer[offset + 1] & 0xFF) << 8) | (buffer[offset + 2] & 0xFF);
            if (tlsVersion < 0x0301) {
                offset++;
                continue;
            }

            int recordLen = ((buffer[offset + 3] & 0xFF) << 8) | (buffer[offset + 4] & 0xFF);
            if (recordLen <= 0 || recordLen > 16384) {
                offset++;
                continue;
            }

            // 数据还没收完整
            if (offset + 5 + recordLen > bufLen) return null;

            // 解析 ClientHello
            String sni = parseClientHello(buffer, offset + 5, recordLen);
            if (sni != null) return sni;

            offset += 5 + recordLen;
        }
        return null;
    }

    private String parseClientHello(byte[] data, int recordOffset, int recordLen) {
        if (recordLen < 4) return null;
        if (data[recordOffset] != 0x01) return null; // 不是 ClientHello

        int hsLen = ((data[recordOffset + 1] & 0xFF) << 16)
                | ((data[recordOffset + 2] & 0xFF) << 8)
                | (data[recordOffset + 3] & 0xFF);
        if (recordLen - 4 < hsLen) return null;

        int pos = 4;
        // 跳过 2(version) + 32(random)
        if (pos + 34 > hsLen) return null;
        pos += 34;

        // Session ID
        if (pos >= hsLen) return null;
        int sidLen = data[recordOffset + pos] & 0xFF;
        pos += 1 + sidLen;
        if (pos > hsLen) return null;

        // Cipher Suites
        if (pos + 2 > hsLen) return null;
        int csLen = ((data[recordOffset + pos] & 0xFF) << 8) | (data[recordOffset + pos + 1] & 0xFF);
        pos += 2 + csLen;
        if (pos > hsLen) return null;

        // Compression
        if (pos >= hsLen) return null;
        int compLen = data[recordOffset + pos] & 0xFF;
        pos += 1 + compLen;
        if (pos > hsLen) return null;

        // Extensions
        if (pos + 2 > hsLen) return null;
        int extLen = ((data[recordOffset + pos] & 0xFF) << 8) | (data[recordOffset + pos + 1] & 0xFF);
        pos += 2;
        int end = Math.min(pos + extLen, hsLen);

        while (pos + 4 <= end) {
            int type = ((data[recordOffset + pos] & 0xFF) << 8) | (data[recordOffset + pos + 1] & 0xFF);
            int extDataLen = ((data[recordOffset + pos + 2] & 0xFF) << 8) | (data[recordOffset + pos + 3] & 0xFF);
            pos += 4;

            if (extDataLen < 0 || pos + extDataLen > end) break;

            if (type == 0x0000) { // SNI
                if (pos + 2 > end) return null;
                int listLen = ((data[recordOffset + pos] & 0xFF) << 8) | (data[recordOffset + pos + 1] & 0xFF);
                pos += 2;
                int listEnd = Math.min(pos + listLen, end);

                if (pos + 3 <= listEnd) {
                    int sniType = data[recordOffset + pos] & 0xFF;
                    int sniLen = ((data[recordOffset + pos + 1] & 0xFF) << 8) | (data[recordOffset + pos + 2] & 0xFF);
                    pos += 3;
                    if (sniType == 0x00 && sniLen > 0 && pos + sniLen <= listEnd) {
                        return new String(data, recordOffset + pos, sniLen);
                    }
                }
                return null;
            }
            pos += extDataLen;
        }
        return null;
    }
}
