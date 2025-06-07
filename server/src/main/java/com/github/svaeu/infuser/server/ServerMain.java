package com.github.svaeu.infuser.server;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class ServerMain {
    public static void main(String[] args) {
        try {
            TCPServer server = new TCPServer();
            server.start();
        } catch (SQLException | IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
