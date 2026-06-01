package org.detector.qweovodetect.dpi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class DpiModeService {

    private static final Path CONFIG_PATH = Path.of("dpi-mode.json");
    private final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private final DpiConnectionRegistry connectionRegistry;
    private final TemporaryTargetBlocklist temporaryTargetBlocklist;
    private final AtomicReference<Mode> mode = new AtomicReference<>(loadMode());

    public DpiModeService(DpiConnectionRegistry connectionRegistry,
                          TemporaryTargetBlocklist temporaryTargetBlocklist) {
        this.connectionRegistry = connectionRegistry;
        this.temporaryTargetBlocklist = temporaryTargetBlocklist;
    }

    public Mode currentMode() {
        return mode.get();
    }

    public boolean isAsync() {
        return currentMode() == Mode.ASYNC;
    }

    public synchronized SwitchResult setMode(String rawMode) {
        Mode next = parseMode(rawMode);
        Mode previous = mode.get();
        mode.set(next);
        writeMode(next);
        if (previous == Mode.ASYNC && next == Mode.SYNC) {
            temporaryTargetBlocklist.clear();
        }
        DpiConnectionRegistry.ResetSummary resetSummary = connectionRegistry.resetAll();
        return new SwitchResult(next, resetSummary.tcpRelays(), resetSummary.udpRelays());
    }

    private Mode loadMode() {
        if (!Files.exists(CONFIG_PATH)) {
            return Mode.SYNC;
        }
        try {
            JsonNode root = objectMapper.readTree(CONFIG_PATH.toFile());
            return parseMode(root.path("mode").asText("SYNC"));
        } catch (Exception ignored) {
            return Mode.SYNC;
        }
    }

    private void writeMode(Mode next) {
        try {
            objectMapper.writeValue(CONFIG_PATH.toFile(), Map.of("mode", next.name()));
        } catch (IOException e) {
            throw new IllegalStateException("write dpi mode failed", e);
        }
    }

    private Mode parseMode(String rawMode) {
        if (rawMode == null || rawMode.isBlank()) {
            return Mode.SYNC;
        }
        return switch (rawMode.trim().toUpperCase(Locale.ROOT)) {
            case "ASYNC" -> Mode.ASYNC;
            case "SYNC" -> Mode.SYNC;
            default -> throw new IllegalArgumentException("unsupported dpi mode: " + rawMode);
        };
    }

    public enum Mode {
        SYNC,
        ASYNC
    }

    public record SwitchResult(Mode mode, int tcpRelaysReset, int udpRelaysReset) {
    }
}
