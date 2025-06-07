package com.github.svaeu.infuser.server.database;

import com.github.svaeu.infuser.server.util.SessionLogger;

import java.io.File;
import java.io.IOException;
import java.sql.*;

/**
 * Database connection class (utility) uses Sqlite for lightweight, portable version of the application.
 * This allows server to run anywhere without needing a separate database setup
 */

public final class DBConnection {
    private static final String JDBC_URL= "jdbc:sqlite:";
    private static DBConnection INSTANCE;

    private final Connection connection;

    private DBConnection(String fileName) throws IOException, SQLException {
        final File dbFile;
        dbFile = new File(fileName);

        if (!dbFile.exists()) {
            if (dbFile.createNewFile()) {
                SessionLogger.log(
                        "Database file '" + dbFile + "' created (Not found on startup).",
                        SessionLogger.LogType.IMPORTANT
                );
            }
        }
        this.connection = DriverManager.getConnection(JDBC_URL + dbFile);
        SessionLogger.log(
                "Database initialized successfully (URL=" + JDBC_URL + dbFile + ").",
                SessionLogger.LogType.DEFAULT
        );
    }

    public static synchronized DBConnection getInstance(String path) throws SQLException, IOException {
        if (INSTANCE == null)
            INSTANCE = new DBConnection(path);

        return INSTANCE;
    }

    public Connection getConnection() {
        return connection;
    }

    public void close() {
        try {
            connection.close();
        } catch (SQLException e) {
            SessionLogger.log(
                    "Failed to close database connection: " + e.getMessage(),
                    SessionLogger.LogType.CRITICAL
            );
        }
    }
}