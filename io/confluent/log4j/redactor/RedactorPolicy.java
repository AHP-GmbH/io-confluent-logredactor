/*
 * Copyright (c) 2021, Confluent, Inc.
 * Copyright (c) 2015, Cloudera, Inc. All Rights Reserved.
 *
 * Cloudera, Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"). You may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for
 * the specific language governing permissions and limitations under the
 * License.
 */

package io.confluent.log4j.redactor;

import io.confluent.logredactor.internal.StringRedactorEngine;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import org.apache.log4j.Logger;
import org.apache.log4j.rewrite.RewritePolicy;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.OptionHandler;
import org.apache.log4j.spi.ThrowableInformation;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.message.Message;
import org.apache.logging.log4j.message.SimpleMessage;

/**
 * <code>RewritePolicy</code> implementation that applies the redaction
 * rules defined in the configuration of the <code>RedactorPolicy</code> in
 * the Log4j Properties configuration file.
 *
 * @see RedactorAppender for the redaction rules definition and syntax.
 */
public class RedactorPolicy implements RewritePolicy, OptionHandler {

  private static final Logger logger = Logger.getLogger(RedactorPolicy.class);
  private StringRedactorEngine engine;
  private String rulesLocation = StringRedactorEngine.DEFAULT_RULES_LOCATION;
  private long refreshIntervalMillis = StringRedactorEngine.DEFAULT_REFRESH_INTERVAL_MILLIS;
  private int urlReaderTimeoutMillis = StringRedactorEngine.DEFAULT_URL_READER_TIMEOUT_MILLIS;
  private LogRedactorMetrics metrics = StringRedactorEngine.DEFAULT_METRICS;

  /**
   * Log4j configurator calls this method with the value found in the config file.
   * @param metricsClassName The metrics class name that is being instantiated.
   */
  public void setMetrics(String metricsClassName) {
    try {
      Class<?> metricsClass = this.getClass().getClassLoader().loadClass(metricsClassName);
      if (LogRedactorMetrics.class.isAssignableFrom(metricsClass)) {
        Constructor<?> constructor = metricsClass.getConstructor();
        LogRedactorMetrics metrics = (LogRedactorMetrics) constructor.newInstance();
        this.metrics = metrics;
      }
    } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
      logger.warn("Unable to load custom metrics class: " + metricsClassName + ". Exception: " + e.getMessage(), e);
    }
  }

  /**
   * Log4j configurator calls this method with the value found in the config file.
   * @param rules The path to the rules file that is being set.
   */
  public void setRules(String rules) {
    this.rulesLocation = rules;
  }

  /**
   * Log4j configurator calls this method with the value found in the config file.
   * Sets the time interval in milliseconds to check for updates in redaction rules.
   * We only check for updates when this positive, and it is negative by default.
   * @param interval The refresh interval that is being set.
   */
  public void setRefreshInterval(long interval) {
    this.refreshIntervalMillis = interval;
  }

  /**
   * Log4j configurator calls this method with the value found in the config file.
   * Sets timeout for the URL reader. This is undocumented, and intended only for unit testing.
   * @param timeOut The time out that is being set.
   */
  public void setTimeOut(int timeOut) {
    this.urlReaderTimeoutMillis = timeOut;
  }

  /**
   * Called after all options are passed in via setter methods
   * so that they can be acted on at one time.
   * This implements the OptionHandler interface.
   */
  public synchronized void activateOptions() {
    this.engine = new StringRedactorEngine(
        rulesLocation,
        refreshIntervalMillis,
        urlReaderTimeoutMillis,
        metrics);
  }

  /**
   * Given a LoggingEvent, potentially modify it and return an altered copy.
   * This implements the RewritePolicy interface.
   * @param source LoggingEvent to examine
   * @return Either the original (no changes) or a redacted copy.
   */
  public LoggingEvent rewrite(LoggingEvent source) {
    if (source != null) {
      boolean rewroteSomething = false;

      Object msg = source.getMessage();
      if (msg != null) {
        String original = msg.toString();
        String redacted = engine.getRedactor().redact(original);
        if (!redacted.equals(original)) {
          msg = redacted;
          rewroteSomething = true;
        }
      }

      Throwable thrown = source.getThrowableInformation() == null ? null : source.getThrowableInformation()
          .getThrowable();
      if (thrown != null) {
        Throwable redactedThrown = engine.getRedactor().redact(thrown);
        if (redactedThrown != thrown) {
          thrown = redactedThrown;
          rewroteSomething = true;
        }
      }
      if (rewroteSomething) {
        return new LoggingEvent(source.getFQNOfLoggerClass(), source.getLogger(),
            source.getTimeStamp(), source.getLevel(), msg, thrown);
      }
    }
    return source;
  }
}

