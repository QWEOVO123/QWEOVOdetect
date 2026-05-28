package org.detector.qweovodetect.dpi;

import io.netty.buffer.ByteBuf;
import org.detector.qweovodetect.stats.BlockRuleService;
import org.detector.qweovodetect.stats.StatsService;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class QuicSniDpiEngine {

    private static final byte[] QUIC_V1_INITIAL_SALT = hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    private static final int MAX_PACKETS_PER_FLOW = 8;
    private static final int MAX_CRYPTO_BYTES = 16384;
    private static final long STATE_TTL_MS = 180_000;

    private static final Map<String, FlowState> states = new ConcurrentHashMap<>();

    public static boolean inspect(ByteBuf payload,
                                  String clientIp,
                                  int listenPort,
                                  String targetHost,
                                  int targetPort) {
        if (payload == null || !payload.isReadable()) {
            return false;
        }

        int len = payload.readableBytes();
        if (len < 1200 || len > 65535) {
            return false;
        }

        byte[] packet = new byte[len];
        payload.getBytes(payload.readerIndex(), packet);
        return inspect(packet, clientIp, listenPort, targetHost, targetPort);
    }

    public static boolean inspect(byte[] packet,
                                  String clientIp,
                                  int listenPort,
                                  String targetHost,
                                  int targetPort) {
        if (!looksLikeQuicV1Initial(packet)) {
            return false;
        }

        long now = System.currentTimeMillis();
        cleanupExpired(now);

        String key = listenPort + "|" + clientIp + "|" + targetHost + ":" + targetPort;
        FlowState state = states.computeIfAbsent(key, ignored -> new FlowState());
        synchronized (state) {
            state.lastSeen = now;
            if (state.finished) {
                states.remove(key);
                return false;
            }
            if (state.packetCount >= MAX_PACKETS_PER_FLOW) {
                state.finished = true;
                states.remove(key);
                return false;
            }
            state.packetCount++;

            byte[] crypto = decryptInitialCrypto(packet);
            if (crypto == null || crypto.length == 0) {
                return false;
            }

            if (state.crypto.size() + crypto.length > MAX_CRYPTO_BYTES) {
                state.finished = true;
                states.remove(key);
                return false;
            }

            state.crypto.writeBytes(crypto);
            String sni = parseTlsClientHelloSni(state.crypto.toByteArray());
            if (sni == null) {
                return false;
            }

            state.finished = true;
            states.remove(key);
            System.out.printf("[QUIC:%d] %s -> %s:%d SNI %s%n",
                    listenPort, clientIp, targetHost, targetPort, sni);

            DpiTaskExecutor.executeDb(() -> saveSni(clientIp, listenPort, sni));
            return isBlocked(sni, clientIp, listenPort, targetHost, targetPort);
        }
    }

    private static boolean looksLikeQuicV1Initial(byte[] packet) {
        if (packet == null || packet.length < 7) {
            return false;
        }
        int first = packet[0] & 0xff;
        if ((first & 0x80) == 0 || (first & 0x40) == 0 || ((first & 0x30) >> 4) != 0) {
            return false;
        }
        return uint32(packet, 1) == 1;
    }

    private static byte[] decryptInitialCrypto(byte[] packet) {
        try {
            ParsedHeader header = parseInitialHeader(packet);
            if (header == null || header.version != 1 || header.dcid.length < 8 || header.sampleOffset + 16 > packet.length) {
                return null;
            }

            InitialKeys keys = deriveInitialKeys(header.dcid);
            byte[] unprotected = Arrays.copyOf(packet, packet.length);
            byte[] mask = aesEcb(keys.hp(), Arrays.copyOfRange(packet, header.sampleOffset, header.sampleOffset + 16));

            unprotected[0] = (byte) (unprotected[0] ^ (mask[0] & 0x0f));
            int pnLength = (unprotected[0] & 0x03) + 1;
            if (header.pnOffset + pnLength > packet.length) {
                return null;
            }
            for (int i = 0; i < pnLength; i++) {
                unprotected[header.pnOffset + i] = (byte) (unprotected[header.pnOffset + i] ^ mask[i + 1]);
            }

            long packetNumber = 0;
            for (int i = 0; i < pnLength; i++) {
                packetNumber = (packetNumber << 8) | (unprotected[header.pnOffset + i] & 0xffL);
            }

            int encryptedOffset = header.pnOffset + pnLength;
            int encryptedLength = header.payloadLength - pnLength;
            if (encryptedLength < 16 || encryptedOffset + encryptedLength > packet.length) {
                return null;
            }

            byte[] aad = Arrays.copyOfRange(unprotected, 0, encryptedOffset);
            byte[] ciphertext = Arrays.copyOfRange(packet, encryptedOffset, encryptedOffset + encryptedLength);
            byte[] plain = aesGcmDecrypt(keys.key(), quicNonce(keys.iv(), packetNumber), aad, ciphertext);
            return extractCryptoFrames(plain);
        } catch (Exception e) {
            return null;
        }
    }

    private static ParsedHeader parseInitialHeader(byte[] packet) {
        if (packet.length < 7) {
            return null;
        }

        int first = packet[0] & 0xff;
        if ((first & 0x80) == 0 || (first & 0x40) == 0 || ((first & 0x30) >> 4) != 0) {
            return null;
        }

        int pos = 1;
        long version = uint32(packet, pos);
        pos += 4;

        int dcidLen = packet[pos++] & 0xff;
        if (dcidLen < 1 || pos + dcidLen >= packet.length) {
            return null;
        }
        byte[] dcid = Arrays.copyOfRange(packet, pos, pos + dcidLen);
        pos += dcidLen;

        int scidLen = packet[pos++] & 0xff;
        if (pos + scidLen >= packet.length) {
            return null;
        }
        pos += scidLen;

        VarInt tokenLength = readVarInt(packet, pos);
        if (tokenLength == null) {
            return null;
        }
        pos = tokenLength.nextOffset();
        if (pos + tokenLength.value() >= packet.length) {
            return null;
        }
        pos += (int) tokenLength.value();

        VarInt length = readVarInt(packet, pos);
        if (length == null) {
            return null;
        }
        pos = length.nextOffset();
        int pnOffset = pos;
        int sampleOffset = pnOffset + 4;
        if (length.value() <= 0 || pnOffset + length.value() > packet.length) {
            return null;
        }

        return new ParsedHeader((int) version, dcid, pnOffset, sampleOffset, (int) length.value());
    }

    private static byte[] extractCryptoFrames(byte[] plain) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int pos = 0;
        while (pos < plain.length) {
            int type = plain[pos] & 0xff;
            if (type == 0x00) {
                pos++;
                continue;
            }
            pos++;
            if (type == 0x06) {
                VarInt offset = readVarInt(plain, pos);
                if (offset == null) break;
                pos = offset.nextOffset();
                VarInt length = readVarInt(plain, pos);
                if (length == null) break;
                pos = length.nextOffset();
                if (length.value() < 0 || pos + length.value() > plain.length) break;
                if (offset.value() == out.size()) {
                    out.write(plain, pos, (int) length.value());
                } else if (offset.value() == 0 && out.size() == 0) {
                    out.write(plain, pos, (int) length.value());
                }
                pos += (int) length.value();
                continue;
            }

            break;
        }
        return out.toByteArray();
    }

    private static String parseTlsClientHelloSni(byte[] data) {
        if (data.length < 42 || data[0] != 0x01) {
            return null;
        }

        int hsLen = ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);
        if (hsLen <= 0 || data.length < hsLen + 4) {
            return null;
        }

        int pos = 4 + 2 + 32;
        if (pos >= data.length) return null;

        int sidLen = data[pos++] & 0xff;
        pos += sidLen;
        if (pos + 2 > data.length) return null;

        int csLen = u16(data, pos);
        pos += 2 + csLen;
        if (pos >= data.length) return null;

        int compLen = data[pos++] & 0xff;
        pos += compLen;
        if (pos + 2 > data.length) return null;

        int extLen = u16(data, pos);
        pos += 2;
        int end = Math.min(pos + extLen, data.length);
        while (pos + 4 <= end) {
            int type = u16(data, pos);
            int len = u16(data, pos + 2);
            pos += 4;
            if (pos + len > end) return null;

            if (type == 0x0000) {
                return parseSniExtension(data, pos, len);
            }
            pos += len;
        }
        return null;
    }

    private static String parseSniExtension(byte[] data, int pos, int len) {
        int end = pos + len;
        if (pos + 2 > end) return null;
        int listLen = u16(data, pos);
        pos += 2;
        int listEnd = Math.min(pos + listLen, end);
        while (pos + 3 <= listEnd) {
            int nameType = data[pos++] & 0xff;
            int nameLen = u16(data, pos);
            pos += 2;
            if (pos + nameLen > listEnd) return null;
            if (nameType == 0 && nameLen > 0) {
                return new String(data, pos, nameLen, StandardCharsets.US_ASCII);
            }
            pos += nameLen;
        }
        return null;
    }

    private static InitialKeys deriveInitialKeys(byte[] dcid) throws Exception {
        byte[] initialSecret = hkdfExtract(QUIC_V1_INITIAL_SALT, dcid);
        byte[] clientSecret = hkdfExpandLabel(initialSecret, "client in", new byte[0], 32);
        return new InitialKeys(
                hkdfExpandLabel(clientSecret, "quic key", new byte[0], 16),
                hkdfExpandLabel(clientSecret, "quic iv", new byte[0], 12),
                hkdfExpandLabel(clientSecret, "quic hp", new byte[0], 16));
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return mac.doFinal(ikm);
    }

    private static byte[] hkdfExpandLabel(byte[] secret, String label, byte[] context, int length) throws Exception {
        byte[] fullLabel = ("tls13 " + label).getBytes(StandardCharsets.US_ASCII);
        ByteBuffer info = ByteBuffer.allocate(2 + 1 + fullLabel.length + 1 + context.length);
        info.putShort((short) length);
        info.put((byte) fullLabel.length);
        info.put(fullLabel);
        info.put((byte) context.length);
        info.put(context);
        return hkdfExpand(secret, info.array(), length);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] previous = new byte[0];
        int counter = 1;
        while (out.size() < length) {
            mac.reset();
            mac.update(previous);
            mac.update(info);
            mac.update((byte) counter++);
            previous = mac.doFinal();
            out.write(previous);
        }
        return Arrays.copyOf(out.toByteArray(), length);
    }

    private static byte[] aesEcb(byte[] key, byte[] block) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher.doFinal(block);
    }

    private static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext);
    }

    private static byte[] quicNonce(byte[] iv, long packetNumber) {
        byte[] nonce = Arrays.copyOf(iv, iv.length);
        for (int i = 0; i < 8; i++) {
            nonce[nonce.length - 1 - i] ^= (byte) (packetNumber >>> (8 * i));
        }
        return nonce;
    }

    private static VarInt readVarInt(byte[] data, int offset) {
        if (offset >= data.length) return null;
        int first = data[offset] & 0xff;
        int prefix = first >>> 6;
        int len = 1 << prefix;
        if (offset + len > data.length) return null;

        long value = first & 0x3fL;
        for (int i = 1; i < len; i++) {
            value = (value << 8) | (data[offset + i] & 0xffL);
        }
        return new VarInt(value, offset + len);
    }

    private static long uint32(byte[] data, int offset) {
        return ((data[offset] & 0xffL) << 24)
                | ((data[offset + 1] & 0xffL) << 16)
                | ((data[offset + 2] & 0xffL) << 8)
                | (data[offset + 3] & 0xffL);
    }

    private static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    private static byte[] hex(String text) {
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static void saveSni(String clientIp, int listenPort, String sni) {
        try {
            StatsService statsService = SpringContextHolder.getBean(StatsService.class);
            if (statsService != null) {
                statsService.saveSni(clientIp, listenPort, sni, "QUIC");
            }
        } catch (Exception e) {
            System.out.println("[QUIC] save failed: " + e.getMessage());
        }
    }

    private static boolean isBlocked(String sni,
                                     String clientIp,
                                     int listenPort,
                                     String targetHost,
                                     int targetPort) {
        try {
            BlockRuleService blockRuleService = SpringContextHolder.getBean(BlockRuleService.class);
            String keyword = blockRuleService.firstMatchedKeyword(sni);
            if (keyword == null) {
                return false;
            }
            System.out.printf("[BLOCK:QUIC:%d] %s -> %s:%d sni=%s keyword=%s%n",
                    listenPort, clientIp, targetHost, targetPort, sni, keyword);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static void cleanupExpired(long now) {
        states.entrySet().removeIf(entry -> now - entry.getValue().lastSeen > STATE_TTL_MS);
    }

    private static class FlowState {
        private final ByteArrayOutputStream crypto = new ByteArrayOutputStream();
        private long lastSeen = System.currentTimeMillis();
        private int packetCount;
        private boolean finished;
    }

    private record ParsedHeader(int version, byte[] dcid, int pnOffset, int sampleOffset, int payloadLength) {
    }

    private record InitialKeys(byte[] key, byte[] iv, byte[] hp) {
    }

    private record VarInt(long value, int nextOffset) {
    }
}
