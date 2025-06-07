package com.github.svaeu.infuser.client;

import com.github.svaeu.infuser.client.usrinterface.Interface;

public class ClientMain {
    private final static String CORRECT_USAGE =
            "Usage: java -jar infuser.jar <ip> <port> [Optional:--nogui]";

    public static void main(String[] args) {
        final TCPClient client;
        final String ip;
        final int port;
        Interface clientInterface;

        if(args.length < 2) {
            System.out.println(CORRECT_USAGE);
            return;
        }
        ip = args[0];

        try{
            port = Integer.parseInt(args[1]);
        } catch (NumberFormatException e) {
            System.out.println("Failed to initialize client: Port must be a valid integer.");
            System.out.println(CORRECT_USAGE);
            return;
        }
        clientInterface = parseInterface(args);
        if(clientInterface == null) return;

        client = new TCPClient(ip, port, clientInterface);
        client.initialize().start();
    }

    private static Interface parseInterface(String[] args) {
        if (args.length < 3) return Interface.GUI;

        if ("--nogui".equalsIgnoreCase(args[2]))
            return Interface.COMMAND_LINE;
        else {
            System.out.println(CORRECT_USAGE);
            return null;
        }
    }
}
