package org.detector.qweovodetect.stats;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class LoginRateLimiter {

    private static final int MAX_FAILED_ATTEMPTS = 8;
    private static final long LOCK_MILLIS = Duration.ofMinutes(1).toMillis();

    private final AtomicInteger failedAttempts = new AtomicInteger();
    private volatile long lockedUntil;

    public boolean isLimited() {
        return lockedUntil > System.currentTimeMillis();
    }

    public long retryAfterSeconds() {
        long remaining = lockedUntil - System.currentTimeMillis();
        return Math.max(1, (remaining + 999) / 1000);
    }

    public void recordSuccess() {
        failedAttempts.set(0);
        lockedUntil = 0;
    }

    public void recordFailure() {
        int failures = failedAttempts.incrementAndGet();
        if (failures >= MAX_FAILED_ATTEMPTS) {
            lockedUntil = System.currentTimeMillis() + LOCK_MILLIS;
            failedAttempts.set(0);
        }
    }
}
