/*
 * Copyright (c) 2021, Confluent, Inc.
 */

package io.confluent.logredactor.internal;

import static io.confluent.log4j.redactor.LogRedactorMetrics.COUNT_ERROR;
import static io.confluent.log4j.redactor.LogRedactorMetrics.TIMER_READ_POLICY_SECONDS;

import io.confluent.log4j.redactor.LogRedactorMetrics;
import io.confluent.logredactor.internal.MetricsTagBuilder.ErrorCode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ThreadLocalRandom;

import org.apache.log4j.Logger;

/**
 * This class contains the logic for starting a background thread,
 * that actively checks for updates in redaction policy, fetches and
 * compiles the new policy for the log redactor to use.
 */
public class StringRedactorEngine {

    public static final long DEFAULT_REFRESH_INTERVAL_MILLIS = -1;
    public static final int DEFAULT_URL_READER_TIMEOUT_MILLIS = 60000;
    public static final LogRedactorMetrics DEFAULT_METRICS = LogRedactorMetrics.NOOP;
    public static final String DEFAULT_RULES_LOCATION = "";
    private static final Logger logger = Logger.getLogger("redactorPolicy");
    public static Queue<Thread> backgroundThreads = new ConcurrentLinkedQueue<>();


    private Thread backgroundThread;
    private String latestPolicyContents;
    private StringRedactor redactor;
    private final String rulesLocation;
    private final long refreshIntervalMillis;
    private final int urlReaderTimeoutMillis;
    public final LogRedactorMetrics metrics;


    class BackgroundRefresher implements Runnable {
        @Override
        public void run() {
            ThreadLocalRandom rand = ThreadLocalRandom.current();
            while (!Thread.currentThread().isInterrupted()){
                try {
                    readAndCompileRules();
                    long sleepMillis = 1 + (refreshIntervalMillis / 2) + rand.nextLong(refreshIntervalMillis / 2);
                    Thread.sleep(sleepMillis);
                } catch (InterruptedException e) {
                    logger.warn("Background refresher thread completing due to interruption: " + e.getMessage());
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public StringRedactorEngine(String rulesLocation, long refreshInterval, int timeOut, LogRedactorMetrics metrics) {
        this.rulesLocation = rulesLocation.trim();
        this.refreshIntervalMillis = refreshInterval;
        this.urlReaderTimeoutMillis = timeOut;
        this.metrics = metrics;
        readAndCompileRules();

        if (this.rulesLocation.isEmpty()) {
            logger.error("No URI nor file location is provided for the rules.");
        }
        else if (this.refreshIntervalMillis > 0) {
            this.backgroundThread = new Thread(new BackgroundRefresher(), "logredactor-refresher");
            this.backgroundThread.setDaemon(true); // This makes it so the JVM won't wait for the thread to shutdown if it's the only one running
            this.backgroundThread.start();
            backgroundThreads.add(this.backgroundThread);
        }
    }

    /**
     * Returns the current redactor
     * @return A StringRedactor object
     */
    public synchronized StringRedactor getRedactor() {
        return redactor;
    }

    /**
     * Read the string content of that specified location contains for later comparison
     * @return A string that contains redaction policy content
     */
    private String readRules() {
        long startTime = System.currentTimeMillis();
        logger.debug("Reading rules from " + rulesLocation);
        String result = "";
        if (rulesLocation.isEmpty()) {
            // do nothing
        } else if (rulesLocation.startsWith("http")) {
            try {
                result = UrlReader.urlToString(rulesLocation, urlReaderTimeoutMillis);
            } catch (IOException e) {
                logger.warn("Failed while reading redactor policy URL: " + rulesLocation, e);
                metrics.count(COUNT_ERROR, new MetricsTagBuilder()
                    .policyLocation(rulesLocation)
                    .errorCode(ErrorCode.READ_ERROR)
                    .build());
            }
        } else {
            try {
                result = readFile(rulesLocation);
            } catch (IOException e) {
                logger.warn("Failed while reading redactor policy file: " + rulesLocation, e);
                metrics.count(COUNT_ERROR, new MetricsTagBuilder()
                    .policyLocation(rulesLocation)
                    .errorCode(ErrorCode.READ_ERROR)
                    .build());
            }
        }
        double elapsed = (System.currentTimeMillis() - startTime) / 1000d;
        metrics.timer(elapsed, TIMER_READ_POLICY_SECONDS, new MetricsTagBuilder()
            .policyLocation(rulesLocation)
            .policyContent(result)
            .build());
        logger.debug("Read redaction rules from " + rulesLocation + " was successful");
        return result;
    }

    /**
     * Set the StringRedactor and latesRawConfig with new JSON rules
     * If there is an error, do not set anything (use the old redactor and rules)
     * @param: JSON rule that needs to be configured
     */
    private void compileRules(String rulesJson, String rulesLocation) {
        // only call whenever detect a change and want to make the change
        try {
            StringRedactor newRulesRedactor = StringRedactor.createFromJsonString(rulesJson, rulesLocation, metrics);
            synchronized (StringRedactorEngine.this) {
                StringRedactorEngine.this.latestPolicyContents = rulesJson;
                StringRedactorEngine.this.redactor = newRulesRedactor;
            }
            logger.debug("Updated rules from " + rulesLocation);
        } catch (IOException e) {
            synchronized (StringRedactorEngine.this) {
                if (StringRedactorEngine.this.redactor == null) {
                    StringRedactorEngine.this.redactor = StringRedactor.emptyStringRedactor(metrics, new MetricsTagBuilder()
                        .policyLocation(rulesLocation)
                        .policyContent(rulesJson)
                        .build());
                }
            }
            if (logger.isDebugEnabled()) {
                logger.error("Error while compiling redactor rules:" + e.getMessage() + "\n Rules: " + rulesJson);
            } else {
                logger.error("Error while compiling redactor rules:" + e.getMessage());
            }
            // emit a metric: Count errors encountered while trying to fetch or parse the policy
            metrics.count(COUNT_ERROR, new MetricsTagBuilder()
                .policyLocation(rulesLocation)
                .errorCode(ErrorCode.PARSE_ERROR)
                .build());
        }
    }

    /**
     * Function used to check for redaction rules updates and calls compileRules
     * Called in the driver and activateOptions
     */
    private void readAndCompileRules() {
        // get the new JSON string
        String latest = readRules();
        // if the new JSON string is different compared to the last JSON string we stored
        if (!latest.equals(latestPolicyContents)) {
            compileRules(latest, rulesLocation);
        }
        redactor.measureRuleCount();
    }

    /**
     * Helper function that reads a file content to a string
     */
    private String readFile(String file) throws IOException {
        return new String(Files.readAllBytes(Paths.get(file)));
    }

    /**
     * Function that closes background threads
     * Used only for testing
     */
    public static void closeBackgroundThreads() {
        for (Thread t = backgroundThreads.poll(); t != null; t = backgroundThreads.poll())
            t.interrupt();
        }
    }

