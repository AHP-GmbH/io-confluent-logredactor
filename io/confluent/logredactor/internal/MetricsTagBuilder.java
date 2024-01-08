/*
 * Copyright (c) 2021, Confluent, Inc.
 */

package io.confluent.logredactor.internal;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.CRC32;

/**
 * This class provides a simple way to create tags for metrics that are defined and used in
 * <code>LogRedactorMetrics</code>.
 */
public class MetricsTagBuilder {

  private static final String POLICY_LOCATION = "policy_location";
  private static final String POLICY_HASH = "policy_hash";
  private static final String ERROR_CODE = "error_code";
  private static final String RULE = "rule";

  public enum ErrorCode {
    READ_ERROR,
    PARSE_ERROR
  }

  private Map<String, String> map = new HashMap<>();

  public MetricsTagBuilder policyLocation(String policyLocation) {
    map.put(POLICY_LOCATION, (policyLocation == null) ? "" : policyLocation);
    return this;
  }

  public MetricsTagBuilder policyContent(String content) {
    map.put(POLICY_HASH, (content == null || content.isEmpty()) ? "" : hashString(content));
    return this;
  }

  public MetricsTagBuilder policyHash(String hash) {
    map.put(POLICY_HASH, (hash == null) ? "" : hash);
    return this;
  }

  public MetricsTagBuilder errorCode(ErrorCode errorCode) {
    map.put(ERROR_CODE, errorCode.name().toLowerCase());
    return this;
  }

  public MetricsTagBuilder rule(String ruleId) {
    map.put(RULE, (ruleId == null) ? "" : ruleId);
    return this;
  }

  public Map<String, String> build() {
    return map;
  }

  private static String hashString(String input) {
    byte[] bytes = input.getBytes(UTF_8);
    try {
      byte[] hashed = MessageDigest.getInstance("SHA-256").digest(bytes);
      StringBuilder sb = new StringBuilder(hashed.length * 2);
      for (byte b : hashed) {
        sb.append(String.format("%02x", b));
      }
      return sb.toString();
    } catch (NoSuchAlgorithmException e) {
      CRC32 checksum = new CRC32();
      checksum.update(bytes, 0, bytes.length);
      return Long.toHexString(checksum.getValue());
    }
  }
}