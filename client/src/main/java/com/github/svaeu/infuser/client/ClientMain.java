package com.github.svaeu.infuser.client;

public class ClientMain {
    private final static String CORRECT_USAGE = "Usage: java -jar infuser.jar <ip> <port>";

    public static void main(String[] args) {
        final int port;

        if(args.length < 2) {
            System.out.println(CORRECT_USAGE);
            return;
        }

        try{
            port = Integer.parseInt(args[1]);
        } catch (NumberFormatException e) {
            System.out.println("Failed to initialize client: Port must be a valid integer.");
            System.out.println(CORRECT_USAGE);
            return;
        }

        new TCPClient(args[0], port).initialize().start();
    }
}
