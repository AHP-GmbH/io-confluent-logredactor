/*
 * Copyright (c) 2021, Confluent, Inc.
 */

package io.confluent.logredactor.internal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;

/**
 * This class contains the logic to read a redaction policy into
 * string from a given URL string
 */
public class UrlReader {

    private static volatile String testOverride = null;
    public static void setTestOverride(String testOverride) {
        UrlReader.testOverride = testOverride;
    }

    public static String urlToString(String urlString, int timeOut) throws IOException {
        if (testOverride != null) {
            return testOverride;
        }
        // open a connection to URL
        URL url = new URL(urlString);
        URLConnection connection = url.openConnection();

        // set timeOuts
        connection.setConnectTimeout(timeOut);
        connection.setReadTimeout(timeOut);

        try (InputStream urlData = connection.getInputStream();
             InputStreamReader isr = new InputStreamReader(urlData);
             BufferedReader in = new BufferedReader(isr)) {

            StringBuilder sb = new StringBuilder();
            for (String line = in.readLine(); line != null; line = in.readLine()) {
                sb.append(line);
            }
            return sb.toString();
        }
    }
}

