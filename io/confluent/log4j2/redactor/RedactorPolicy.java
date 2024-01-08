/*
 * Copyright (c) 2021, Confluent, Inc.
 * Copyright (c) 2017, Cloudera, Inc. All Rights Reserved.
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
package io.confluent.log4j2.redactor;

import static io.confluent.logredactor.internal.StringRedactorEngine.DEFAULT_METRICS;
import static io.confluent.logredactor.internal.StringRedactorEngine.DEFAULT_REFRESH_INTERVAL_MILLIS;
import static io.confluent.logredactor.internal.StringRedactorEngine.DEFAULT_RULES_LOCATION;
import static io.confluent.logredactor.internal.StringRedactorEngine.DEFAULT_URL_READER_TIMEOUT_MILLIS;

import io.confluent.log4j.redactor.LogRedactorMetrics;
import io.confluent.logredactor.internal.StringRedactorEngine;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.rewrite.RewritePolicy;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.message.Message;
import org.apache.logging.log4j.message.SimpleMessage;

/**
 * <code>RewritePolicy</code> implementation that applies the redaction
 * rules defined in the configuration of the <code>RedactorPolicy</code> in
 * the Log4j Properties configuration file. Use with RewriteAppender.
 */
@Plugin(name = "RedactorPolicy", category = "Core", elementType = "layout", printObject = true)
public class RedactorPolicy implements RewritePolicy {

  private StringRedactorEngine redactor;

  @PluginFactory
  public static RedactorPolicy createPolicy(@PluginAttribute("name") String name,
                                            @PluginAttribute("rules") String rules,
                                            @PluginAttribute("refreshInterval") Long refreshInterval,
                                            @PluginAttribute("timeOut") Integer timeOut,
                                            @PluginElement("metrics") LogRedactorMetrics metrics) {
    return new RedactorPolicy(
        coalesce(rules, DEFAULT_RULES_LOCATION),
        coalesce(refreshInterval, DEFAULT_REFRESH_INTERVAL_MILLIS),
        coalesce(timeOut, DEFAULT_URL_READER_TIMEOUT_MILLIS),
        coalesce(metrics, DEFAULT_METRICS)
    );
  }

  private RedactorPolicy(String rules, long refreshInterval, int timeOut, LogRedactorMetrics metrics) {
    this.redactor = new StringRedactorEngine(rules, refreshInterval, timeOut, metrics);
  }

  private static <T> T coalesce(T value, T fallback) {
    return (value == null) ? fallback : value;
  }

  /**
   * Given a LoggingEvent, potentially modify it and return an altered copy.
   * This implements the RewritePolicy interface.
   * @param source LoggingEvent to examine
   * @return Either the original (no changes) or a redacted copy.
   */
  public LogEvent rewrite(LogEvent source) {
    if (source != null) {
      Message msg = source.getMessage();
      Throwable thrown = source.getThrown();
      Throwable redactedThrown = null;
      if (thrown != null) {
        redactedThrown = redactor.getRedactor().redact(thrown);
      }
      String redactedMsg = null;
      if (msg != null) {
        String original = msg.getFormattedMessage();
        if (original != null) {
          String redacted = redactor.getRedactor().redact(original);
          if (!redacted.equals(original)) {
            redactedMsg = redacted;
          }
        }
      }
      if (redactedMsg != null || redactedThrown != null) {
        Log4jLogEvent.Builder builder = new Log4jLogEvent.Builder(source);
        if (redactedMsg != null) {
          builder.setMessage(new SimpleMessage(redactedMsg));
        }
        if (redactedThrown != null) {
          builder.setThrown(redactedThrown);
        }
        return builder.build();
      }
    }
    return source;
  }
}

