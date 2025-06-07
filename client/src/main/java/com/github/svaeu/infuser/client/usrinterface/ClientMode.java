package com.github.svaeu.infuser.client.usrinterface;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

public interface ClientMode extends Runnable {
    void displayMessage(String message) throws IOException;
    void displayMedia(byte[] mediaData);

    String prompt(String message) throws ExecutionException, InterruptedException;

    void waitForIt(String message);
    void notifyToResume();

    void shutdown();
}