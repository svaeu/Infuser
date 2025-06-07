package com.github.svaeu.infuser.server.util;

import java.io.*;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

public class SessionLogger {

    private static PrintWriter logWriter = null;

    //server session logger file initialization
    static {
        File logFile;
        String basePath;
        int increment = 1;

        String logDirPath = "server_logs";
        File logDir = new File(logDirPath);

        String logFileName = "session-log-" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("h:mm_d.M.yyyy")) + ".log";
        basePath = logDirPath + File.separator + logFileName;

        logFile = new File(basePath);

        if (!logDir.exists()) {
            if(!logDir.mkdir())
                log("Failed to create directory: " + logDirPath, LogType.IMPORTANT);
        }

        while (logFile.exists()) {
            basePath = logDirPath + File.separator + logFileName.replace(".log", "_(" + increment + ").log");
            logFile = new File(basePath);
            increment++;
        }

        try {
            if (logFile.createNewFile()) {
                log(logFileName + " (FILE) created for this session's logging", LogType.IMPORTANT);
                logWriter = new PrintWriter(new FileWriter(logFile));
            } else { log("Failed to create a log file", LogType.IMPORTANT); }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public enum LogType {
        DEFAULT,
        IMPORTANT,
        CRITICAL,
        INFO
    }

    public static void log(String message, LogType logType) {
        final String typeIdentifier, logMessage;

        if(message == null || message.isEmpty()) return;

        switch(logType) {
            case DEFAULT -> typeIdentifier =  "\u001B[37m[WORKER]";
            case IMPORTANT -> typeIdentifier = "\u001B[33m[!]";
            case CRITICAL -> typeIdentifier = "\u001B[31m[X]";
            case INFO -> typeIdentifier =  "\u001B[37m[*]";

            default ->  typeIdentifier = "";
        }

        logMessage = "["+ LocalTime.now().format(DateTimeFormatter
                .ofPattern("HH:mm:ss")) +"] "+ typeIdentifier +" "+ message+"\033[0m";
        System.out.println(logMessage);

        if(logWriter != null) {
            logWriter.println(logMessage);
            logWriter.flush();
        }
    }
}
