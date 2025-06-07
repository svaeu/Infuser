package com.github.svaeu.infuser.client.util;

import org.jline.reader.LineReader;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

import java.io.IOException;

public class ConsoleLogger {
    private static final Terminal terminal;

    static {
        try {
            terminal = TerminalBuilder.builder().system(true).build();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void log(LineReader lineReader, String message, String color) {
        if (lineReader != null) {
            lineReader.printAbove(color + message + "\033[0m");
        } else {
            terminal.writer().print("\033[0m");
            terminal.writer().println(color + message + "\033[0m");
            terminal.flush();
        }
    }

    public static void error(LineReader lineReader, String message) {
        log(lineReader, "[!] "+message, "\033[31m");
    }

    public static void info(String message) {
        log(null, "[*] "+message, "\033[33m");
    }

    public static Terminal getTerminal() {
        return terminal;
    }
}
