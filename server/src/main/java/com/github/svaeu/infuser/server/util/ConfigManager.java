package com.github.svaeu.infuser.server.util;

import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;

public class ConfigManager {

    private final File settingsFile;

    private Map<String, Object> settings = new HashMap<>();

    public ConfigManager(String path) {
        this.settingsFile = new File(path);
    }

    public void loadConfigurations() throws IOException {
        if(!settingsFile.exists())
            try (InputStream is = getClass().getClassLoader().getResourceAsStream(
                    "config.yml"))
            {
                if(is != null)
                    Files.copy(is, settingsFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                else throw new RuntimeException("default server configuration file could not be loaded " +
                        "as it was not found in the resources folder");
            }
        try(InputStream is = new FileInputStream(settingsFile)) { this.settings = new Yaml().load(is); }
    }

    private Object getNestedValue(String key) {
        Object currentObj;

        if (settings == null) return null;
        currentObj = settings;

        for (String part : key.split("\\.")) {
            if (currentObj instanceof Map) {
                currentObj = ((Map<?, ?>) currentObj).get(part);
            } else {
                return null;
            }
            if (currentObj == null) return null;
        }
        return currentObj;
    }

    public int getServerPort() {
        final Object port = getNestedValue("server.port");
        return port != null ? ((Number) port).intValue() : 1207;
    }

    public boolean getIfWhitelisted() {
        final Object whitelisted = getNestedValue("server.isWhitelisted");
        return whitelisted != null ? (Boolean) whitelisted : false;
    }

    public String getDBFilePath() {
        final Object path = getNestedValue("server.database.path");
        return path != null ? (String) path : "";
    }
}