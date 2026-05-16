package org.detector.qweovodetect.dpi;

import java.nio.charset.StandardCharsets;

/**
 * HTTP Host 提取
 */
public class HttpHostParser {

    public static String parse(byte[] data, String clientIp) {
        if (data == null || data.length < 16) return null;

        String http = new String(data, 0, Math.min(data.length, 4096), StandardCharsets.UTF_8);
        int idx = http.indexOf("Host:");
        if (idx == -1) {
            idx = http.indexOf("host:");
        }
        if (idx == -1) return null;

        int start = idx + 5;
        while (start < http.length() && http.charAt(start) == ' ') start++;

        StringBuilder host = new StringBuilder();
        while (start < http.length()) {
            char c = http.charAt(start);
            if (c == '\r' || c == '\n' || c == ' ' || c == ':') break;
            host.append(c);
            start++;
        }

        if (host.length() == 0) return null;

        String domain = host.toString();
        System.out.printf("[HTTP检测] %s -> %s%n", clientIp, domain);
        return domain;
    }
}