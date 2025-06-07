package com.github.svaeu.infuser.server.database;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class QueryLoader {
    private static final Map<String, String> queries = new HashMap<>();

    static {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                Objects.requireNonNull(QueryLoader.class
                        .getClassLoader()
                        .getResourceAsStream("db_queries.sql"))))
        ) {
            String line;
            String[] queryKV;

            while ((line = reader.readLine()) != null) {
                if (!line.contains("=")) { continue; }

                queryKV = line.split("=", 2);
                queries.put(queryKV[0].trim(), queryKV[1].trim());
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load SQL queries", e);
        }
    }

    public static String get(String key) {
        return queries.get(key);
    }
}
