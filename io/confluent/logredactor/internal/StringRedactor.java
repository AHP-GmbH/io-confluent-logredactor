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

package io.confluent.logredactor.internal;

import static io.confluent.log4j.redactor.LogRedactorMetrics.COUNT_MATCHED_LOG_STATEMENTS;
import static io.confluent.log4j.redactor.LogRedactorMetrics.COUNT_MATCHES;
import static io.confluent.log4j.redactor.LogRedactorMetrics.COUNT_POLICY_UPDATE;
import static io.confluent.log4j.redactor.LogRedactorMetrics.COUNT_REDACTED_LOG_STATEMENTS;
import static io.confluent.log4j.redactor.LogRedactorMetrics.COUNT_REDACTIONS;
import static io.confluent.log4j.redactor.LogRedactorMetrics.COUNT_SCANNED_LOG_STATEMENTS;
import static io.confluent.log4j.redactor.LogRedactorMetrics.GAUGE_POLICY_RULE_COUNT;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonArray;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.JsonValue;
import com.eclipsesource.json.ParseException;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import io.confluent.log4j.redactor.LogRedactorMetrics;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

/**
 * This class contains the logic for redacting Strings. It is initialized
 * from rules contained in a JSON file.
 */
public class StringRedactor {

  private RedactionPolicy policy;

  public static StringRedactor emptyStringRedactor(LogRedactorMetrics metrics, Map<String, String> tags) {
    StringRedactor sr = new StringRedactor();
    sr.policy = RedactionPolicy.emptyRedactionPolicy(metrics, tags);
    return sr;
  }

  // Prevent use of normal constructor
  private StringRedactor() {}

  /**
   * Since we only read from JSON files, we only need setter methods.
   */
  private static class RedactionRule {

    private String description;
    private boolean caseSensitive = true;
    private boolean omitNestedExceptions = false;
    private String trigger;
    private String search;
    private String replace;
    private Pattern pattern;
    private ThreadLocal<Matcher> matcherTL;
    private String metricsId;
    private Map<String, String> tags = new HashMap<>();

    public void setDescription(String description) {
      this.description = description;
    }

    public void setCaseSensitive(boolean caseSensitive) {
      this.caseSensitive = caseSensitive;
    }

    public void setOmitNestedExceptions(boolean omitNestedExceptions) {
      this.omitNestedExceptions = omitNestedExceptions;
    }

    public void setTrigger(String trigger) {
      this.trigger = trigger;
    }

    public void setMetricsId(String metricsId) {
      this.metricsId = metricsId;
      this.tags.put("rule", metricsId);
    }

    public void setTags(Map<String, String> tags) {
      this.tags = new HashMap<>(tags);
      this.tags.put("rule", metricsId);
    }

    public void setSearch(String search) {
      this.search = search;
      // We create a Pattern here to ensure it's a valid regex. We don't
      // set this.pattern because we don't know yet if it's case
      // sensitive or not. That's done in postProcess().
      if (search != null) {
        Pattern thrownAway = Pattern.compile(search);
      }
    }

    public void setReplace(String replace) {
      this.replace = replace;
    }

    private void validateReplacement(Pattern pattern, String replacement) {
      int i = 0;
      int m = replacement.length();
      int groupCount = pattern.groupCount();

      Set<String> namedGroups = Collections.emptySet();
      try {
        namedGroups = pattern.namedGroups().keySet();
      } catch (NullPointerException ignored){
        // See: https://github.com/google/re2j/issues/152
      }


      for (; i < m - 1; i++) {
        if (replacement.charAt(i) == '\\') {
          i++;
          continue;
        }
        if (replacement.charAt(i) == '$') {
          int c = replacement.charAt(i + 1);
          if ('0' <= c && c <= '9') {
            int n = c - '0';
            for (i += 2; i < m; i++) {
              c = replacement.charAt(i);
              if (c < '0' || c > '9' || n * 10 + c - '0' > groupCount) {
                break;
              }
              n = n * 10 + c - '0';
            }
            if (n > groupCount) {
              throw new IndexOutOfBoundsException("Replacement string contains a group number '" + n + "' which is > total number of groups");
            }
            i--;
          } else if (c == '{') {
            i++; // skip {
            int j = i + 1;
            while (j < replacement.length()
                && replacement.charAt(j) != '}'
                && replacement.charAt(j) != ' ') {
              j++;
            }
            if (j == replacement.length() || replacement.charAt(j) != '}') {
              throw new IllegalArgumentException("In replacement string, named capture group is missing trailing '}'");
            }
            String groupName = replacement.substring(i + 1, j);
            if (!namedGroups.contains(groupName)) {
              throw new IllegalArgumentException("Replacement string contains a group '" + groupName + "' which is not found in the pattern");
            }
          }
        }
      }
    }

    private void postProcess() throws RedactionPolicyParseException {
      if ((search == null) || search.isEmpty()) {
        throw new RedactionPolicyParseException("The search regular expression cannot be empty.");
      }

      if (caseSensitive) {
        pattern = Pattern.compile(search);
      } else {
        pattern = Pattern.compile(search, Pattern.CASE_INSENSITIVE);
      }
      matcherTL = ThreadLocal.withInitial(() -> pattern.matcher(""));

      // Actually try a sample search-replace with the search and replace.
      // We know the search is valid from the above, but the replace could
      // be malformed - for example $% is an illegal group reference.
      try {
        String sampleString = "Hello, world";
        Matcher m = pattern.matcher(sampleString);
        if (replace != null) {
          validateReplacement(pattern, replace);
          sampleString = m.replaceAll(replace);
        }
      } catch (Exception e) {
        throw new RedactionPolicyParseException("The replacement text \"" +
            replace + "\" is invalid: " + e.getMessage(), e);

      }
    }

    private boolean matchesTrigger(String msg) {
      // The common case: an empty trigger.
      if ((trigger == null) || trigger.isEmpty()) {
        return true;
      }

      /* TODO Consider Boyer-More for performance.
       * http://www.cs.utexas.edu/users/moore/publications/fstrpos.pdf
       * However, it might not matter much in our use case.
       */
      if (caseSensitive) {
        return msg.contains(trigger);
      }

      // As there is no case-insensitive contains(), our options are to
      // toLower() the strings (creates and throws away objects), use a regex
      // (slow) or write our own using regionMatches(). We take the latter
      // option, as it's fast.
      final int len = trigger.length();
      final int max = msg.length() - len;
      for (int i = 0; i <= max; i++) {
        if (msg.regionMatches(true, i, trigger, 0, len)) {
          return true;
        }
      }
      return false;
    }
  }

  /**
   * This class contains a version number and an array of RedactionRules.
   */
  private static class RedactionPolicy {
    private int version = -1;
    private List<RedactionRule> rules;
    public LogRedactorMetrics metrics;
    public Map<String, String> tags;

    public void setVersion(int version) {
      this.version = version;
    }

    public void setRules(List<RedactionRule> rules) {
      this.rules = rules;
    }

    public void setupMetrics(LogRedactorMetrics metrics, Map<String, String> tags) {
      this.metrics = metrics;
      this.tags = tags;
      Map<String, String> ruleTags = new HashMap<>(tags);
      for (RedactionRule rule : rules) {
        if (rule.metricsId != null) {
          ruleTags.put("rule", rule.metricsId);
          rule.setTags(ruleTags);
        }
      }
      metrics.count(COUNT_POLICY_UPDATE, tags);
      measureRuleCount();
    }


    private static RedactionPolicy emptyRedactionPolicy(LogRedactorMetrics metrics, Map<String, String> tags) {
      RedactionPolicy policy = new RedactionPolicy();
      policy.version = 1;
      policy.rules = new ArrayList<>();
      policy.setupMetrics(metrics, tags);
      return policy;
    }

    /**
     * Perform validation checking on the fully constructed JSON, and
     * sets up internal data structures.
     * @throws RedactionPolicyParseException on version and processing issues.
     */
    private void postProcess() throws RedactionPolicyParseException {
      if (version == -1) {
        throw new RedactionPolicyParseException("No version specified.");
      } else if (version != 1) {
        throw new RedactionPolicyParseException("Unknown version " + version);
      }
      for (RedactionRule rule : rules) {
        rule.postProcess();
      }
    }

    /**
     * The actual work of redaction.
     * @param msg The string to redact
     * @return If any redaction was performed, the redacted string. Otherwise,
     *         the original is returned.
     */
    private String redact(String msg) {
      return redact(msg, null);
    }

    /**
     * The actual work of redaction.
     * @param msg The string to redact
     * @param matchingRuleCallback This callback will be invoked for each matching rule
     * @return If any redaction was performed, the redacted string. Otherwise,
     *         the original is returned.
     */
    private String redact(String msg, Function<RedactionRule, Void> matchingRuleCallback) {
      if (msg == null) {
        return null;
      }
      String original = msg;
      boolean matched = false;
      boolean redacted = false;
      for (RedactionRule rule : rules) {
        if (rule.matchesTrigger(msg)) {
          Matcher m = rule.matcherTL.get();
          m.reset(msg);
          if (m.find()) {
            matched = true;
            if (rule.metricsId != null) {
              metrics.count(COUNT_MATCHES, rule.tags);
            }
            if (rule.replace != null) {
              msg = m.replaceAll(rule.replace);
              redacted = true;
              if (rule.metricsId != null) {
                metrics.count(COUNT_REDACTIONS, rule.tags);
              }
            }
            if (matchingRuleCallback != null) {
              matchingRuleCallback.apply(rule);
            }
          }
        }
      }
      metrics.count(COUNT_SCANNED_LOG_STATEMENTS, this.tags);
      if (matched) {
        metrics.count(COUNT_MATCHED_LOG_STATEMENTS, this.tags);
      }
      if (redacted) {
        metrics.count(COUNT_REDACTED_LOG_STATEMENTS, this.tags);
        return msg;
      }
      else {
        return original;
      }
    }

    public void measureRuleCount() {
      metrics.gauge(rules.size(), GAUGE_POLICY_RULE_COUNT, tags);
    }
  }

  /**
   * Create a StringRedactor based on the JSON found in a file. The file
   * format looks like this:
   * <pre>
   * {
   *   "version": "1",
   *   "rules": [
   *     { "description": "This is the first rule",
   *       "trigger": "triggerstring 1",
   *       "search": "regex 1",
   *       "replace": "replace 1"
   *     },
   *     { "description": "This is the second rule",
   *       "trigger": "triggerstring 2",
   *       "search": "regex 2",
   *       "replace": "replace 2"
   *     }
   *   ]
   * }
   * </pre>
   * @param fileName The name of the file to read
   * @return A freshly allocated StringRedactor
   * @throws java.io.IOException
   * We convert jackson exceptions to RedactionPolicyParseExceptions
   * because we shade and relocate jackson and don't want to expose it.
   */
  public static StringRedactor createFromJsonFile(String fileName)
          throws IOException {
    return createFromJsonFile(fileName, LogRedactorMetrics.NOOP);
  }

  public static StringRedactor createFromJsonFile(String fileName, LogRedactorMetrics metrics)
          throws IOException {
    StringRedactor sr = new StringRedactor();

    if (fileName == null) {
      sr.policy = RedactionPolicy.emptyRedactionPolicy(metrics, new MetricsTagBuilder()
          .policyLocation("")
          .policyHash("")
          .build());
      return sr;
    }
    File file = new File(fileName);
    // An empty file is explicitly allowed as "no rules"
    if (file.exists() && file.length() == 0) {
      sr.policy = RedactionPolicy.emptyRedactionPolicy(metrics, new MetricsTagBuilder()
          .policyLocation(fileName)
          .policyHash("")
          .build());
      return sr;
    }

    String content = new String(Files.readAllBytes(Paths.get(fileName)));
    return createFromJsonString(content, fileName, metrics);
  }

  /**
   * Create a StringRedactor based on the JSON found in the given String.
   * The format is identical to that described in createFromJsonFile().
   * @param json String containing json formatted rules.
   * @param rulesLocation String containing location of the redaction rules.
   * @return A freshly allocated StringRedactor
   * @throws java.io.IOException
   * We convert jackson exceptions to RedactionPolicyParseExceptions
   * because we shade and relocate jackson and don't want to expose it.
   */
  public static StringRedactor createFromJsonString(String json, String rulesLocation)
          throws IOException {
    return createFromJsonString(json, rulesLocation, LogRedactorMetrics.NOOP);
  }

  public static StringRedactor createFromJsonString(String json, String rulesLocation, LogRedactorMetrics metrics)
          throws IOException {
    StringRedactor sr = new StringRedactor();
    if ((json == null) || json.isEmpty() || (rulesLocation == null) || rulesLocation.isEmpty()) {
      sr.policy = RedactionPolicy.emptyRedactionPolicy(metrics, new MetricsTagBuilder()
          .policyLocation(rulesLocation)
          .policyContent(json)
          .build());
      return sr;
    }

    RedactionPolicy policy;
    try {
      policy = createPolicyFromJson(json);
    } catch (RedactionPolicyParseException | RuntimeException e) {
      throw new RedactionPolicyParseException(e.getMessage(), e.getCause());
    }

    policy.postProcess();
    sr.policy = policy;
    sr.policy.setupMetrics(metrics, new MetricsTagBuilder()
        .policyLocation(rulesLocation)
        .policyContent(json)
        .build());
    return sr;
  }

  private static RedactionPolicy createPolicyFromJson(String json) throws RedactionPolicyParseException, ParseException {

    // Set up new redaction policy
    RedactionPolicy policy = new RedactionPolicy();
    JsonObject jo = Json.parse(json).asObject();

    // Make sure there are no extra fields
    if (jo.size() > 2) {
      throw new RedactionPolicyParseException("Too many fields");
    }

    // Set version
    int policyVersion;
    JsonValue version = jo.get("version");
    if (version != null) {
      if (version.isString()) { // See if string can be converted to int
        String strVersion = version.asString();
        policyVersion = Integer.parseInt(strVersion);
      } else if (version.isNumber()){
        policyVersion = jo.getInt("version", -1);
      } else {
        throw new RedactionPolicyParseException("Not a number");
      }
      policy.setVersion(policyVersion);
    }

    // Set up list of redaction rules
    JsonArray rules = jo.get("rules").asArray();
    List<RedactionRule> policyRules = new ArrayList<>();

    // Set up each redaction rule one by one
    for (JsonValue rule: rules) {
      RedactionRule newRule = new RedactionRule();
      String description = rule.asObject().getString("description", null);
      newRule.setDescription(description);

      boolean caseSensitive = parseBoolean(rule, "caseSensitive", true);
      newRule.setCaseSensitive(caseSensitive);

      boolean omitNestedExceptions = parseBoolean(rule, "omitNestedExceptions", false);
      newRule.setOmitNestedExceptions(omitNestedExceptions);

      String trigger = rule.asObject().getString("trigger", null);
      newRule.setTrigger(trigger);

      String search = rule.asObject().getString("search", null);
      newRule.setSearch(search);

      String replace = rule.asObject().getString("replace", null);
      newRule.setReplace(replace);

      String metricsId = rule.asObject().getString("metricsId", null);
      newRule.setMetricsId(metricsId);

      System.out.println(rule);
      policyRules.add(newRule);
    }
    policy.setRules(policyRules);
    return policy;
  }

  private static boolean parseBoolean(JsonValue rule, String name, boolean defaultValue) throws RedactionPolicyParseException {
    // We support both String or boolean types for boolean parameters
    boolean value = defaultValue;
    JsonValue policyBooleanValue = rule.asObject().get(name);
    if (policyBooleanValue != null) {
      if (policyBooleanValue.isString()) {
        // If String then convert it to boolean
        String strValue = policyBooleanValue.asString();
        value = Boolean.parseBoolean(strValue);
      } else if (policyBooleanValue.isBoolean()) {
        value = rule.asObject().getBoolean(name, defaultValue);
      } else {
        throw new RedactionPolicyParseException("Not a boolean");
      }
    }
    return value;
  }

  /**
   * The actual redaction - given a message, look through the list of
   * redaction rules and apply if matching. If so, return the redacted
   * String, else return the original string.
   * @param msg The message to examine.
   * @return The (potentially) redacted message.
   */
  public String redact(String msg) {
    return policy.redact(msg);
  }

  public Throwable redact(Throwable t) {
    if (t != null) {
      String msg = t.getMessage();
      // No race-condition here to use AtomicBoolean; it's just that we need a getter/setter
      // for boolean; because Java lambda won't allow none final primitives.
      final AtomicBoolean omitNestedExceptions = new AtomicBoolean(false);
      String redactedMsg = policy.redact(msg, rule -> {
        // We omit nested exceptions if any one of the matching rules specifies so
        if (rule.omitNestedExceptions) {
          omitNestedExceptions.set(true);
        }
        return null;
      });

      Throwable cause = t.getCause();
      Throwable redactedCause = (omitNestedExceptions.get() ? null : redact(cause));

      // Note, we intentionally use object reference equality in the following conditional:
      if ((redactedMsg != msg) || (redactedCause != cause)) {
        Throwable redacted;
        try {
          redacted = t.getClass()
              .getDeclaredConstructor(String.class, Throwable.class)
              .newInstance(redactedMsg, redactedCause);
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException |
                 InvocationTargetException | RuntimeException e) {
          redacted = new Throwable(redactedMsg, redactedCause);
        }
        redacted.setStackTrace(t.getStackTrace());
        return redacted;
      }
    }
    return t;
  }

  public void measureRuleCount() {
    policy.measureRuleCount();
  }
}