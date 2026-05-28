package org.detector.qweovodetect.dpi;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class DpiTaskExecutor {

    private static final int WORKERS = Math.max(2, Runtime.getRuntime().availableProcessors());
    private static final int QUEUE_SIZE = 4096;

    private static final ExecutorService DPI_POOL = new ThreadPoolExecutor(
            WORKERS,
            WORKERS,
            0L,
            TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(QUEUE_SIZE),
            new ThreadPoolExecutor.CallerRunsPolicy()
    );

    private static final ExecutorService DB_POOL = new ThreadPoolExecutor(
            1,
            1,
            0L,
            TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(QUEUE_SIZE),
            new ThreadPoolExecutor.CallerRunsPolicy()
    );

    private DpiTaskExecutor() {
    }

    public static void executeDpi(Runnable task) {
        DPI_POOL.execute(task);
    }

    public static void executeDb(Runnable task) {
        DB_POOL.execute(task);
    }
}
