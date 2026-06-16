package org.detector.qweovodetect.dpi;

import java.nio.charset.StandardCharsets;

public class HttpHostParser {

    private static final int MAX_HEADER_SCAN = 4096;

    public static String parse(byte[] data, String clientIp) {
        if (data == null || data.length < 16) {
            return null;
        }

        int limit = Math.min(data.length, MAX_HEADER_SCAN);
        int headerEnd = findHeaderEnd(data, limit);
        if (headerEnd != -1) {
            limit = headerEnd;
        }

        int lineStart = 0;
        while (lineStart < limit) {
            int lineEnd = lineStart;
            while (lineEnd < limit && data[lineEnd] != '\r' && data[lineEnd] != '\n') {
                lineEnd++;
            }

            int valueStart = hostValueStart(data, lineStart, lineEnd);
            if (valueStart != -1) {
                int valueEnd = valueStart;
                while (valueEnd < lineEnd) {
                    byte b = data[valueEnd];
                    if (b == ' ' || b == '\t' || b == ':') {
                        break;
                    }
                    valueEnd++;
                }
                if (valueEnd > valueStart) {
                    return new String(data, valueStart, valueEnd - valueStart, StandardCharsets.ISO_8859_1);
                }
                return null;
            }

            lineStart = lineEnd + 1;
            if (lineStart < limit && data[lineStart - 1] == '\r' && data[lineStart] == '\n') {
                lineStart++;
            }
        }

        return null;
    }

    private static int hostValueStart(byte[] data, int lineStart, int lineEnd) {
        if (lineEnd - lineStart < 5) {
            return -1;
        }
        if (!equalsIgnoreCase(data[lineStart], 'h')
                || !equalsIgnoreCase(data[lineStart + 1], 'o')
                || !equalsIgnoreCase(data[lineStart + 2], 's')
                || !equalsIgnoreCase(data[lineStart + 3], 't')
                || data[lineStart + 4] != ':') {
            return -1;
        }

        int start = lineStart + 5;
        while (start < lineEnd && (data[start] == ' ' || data[start] == '\t')) {
            start++;
        }
        return start;
    }

    private static int findHeaderEnd(byte[] data, int limit) {
        for (int i = 0; i + 3 < limit; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static boolean equalsIgnoreCase(byte actual, char expectedLowercase) {
        int value = actual & 0xff;
        if (value >= 'A' && value <= 'Z') {
            value += 'a' - 'A';
        }
        return value == expectedLowercase;
    }
}
