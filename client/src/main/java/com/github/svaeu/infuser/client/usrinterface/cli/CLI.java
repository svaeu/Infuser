package com.github.svaeu.infuser.client.usrinterface.cli;

import com.github.svaeu.infuser.client.TCPClient;
import com.github.svaeu.infuser.client.usrinterface.ClientMode;
import com.github.svaeu.infuser.client.usrinterface.cli.command.CLICommand;
import com.github.svaeu.infuser.client.util.ConsoleLogger;
import com.github.svaeu.infuser.packets.Packet;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.terminal.Terminal;
import org.jline.utils.InfoCmp;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

public class CLI implements ClientMode {

    private ExecutorService executorService = Executors.newSingleThreadExecutor();
    private final AtomicReference<Future<String>> currentReader = new AtomicReference<>();

    private final LineReader reader = LineReaderBuilder.builder().terminal(ConsoleLogger.getTerminal()).build();
    private boolean isReading;

    private final Set<CLICommand> consoleCommands;

    private Thread waitThread;
    private String waitMessage;

    private final TCPClient tcpClient;

    public CLI(TCPClient tcpClient, Set<CLICommand> commands) {
        this.tcpClient = tcpClient;
        this.consoleCommands = commands;
    }

    @Override
    public void displayMessage(String message) {
        ConsoleLogger.log(reader, message, "");
    }

    @Override
    public void displayMedia(byte[] mediaData) {}

    @Override
    public String prompt(String message) throws ExecutionException, InterruptedException {
        final Future<String> oldTask, newTask;

        oldTask = currentReader.getAndSet(null);
        if(oldTask != null) oldTask.cancel(true);

        newTask = executorService.submit(() -> reader.readLine("\u001B[36m" + message + "\033[0m "));
        currentReader.set(newTask);

        try{
            return newTask.get();
        } catch (CancellationException e) {
            return null;
        }
    }

    @Override
    public synchronized void shutdown() {
        Future<String> current;

        current = currentReader.getAndSet(null);
        if (current != null) {
            current.cancel(true);
        }
        executorService.shutdownNow();

        try {
            if (reader != null && reader.getTerminal() != null) {
                reader.getTerminal().close();
            }
        } catch (Exception e) {
            ConsoleLogger.error(reader,"Response reader cleanup failed: " + e.getMessage());
        }
    }

    @Override
    public void run() {
        while (!Thread.currentThread().isInterrupted()) {
            if (executorService.isShutdown()) executorService = Executors.newSingleThreadExecutor();
            try {
                String clientInput, roomPrefix = "";
                String[] cmdArgs;

                if(!isReading) continue;

                if(tcpClient.getCrtChannel() != null)
                    roomPrefix += "["+tcpClient.getCrtChannel().getTitle()+"] ("+tcpClient.getCrtChannel().getStrength()
                            +"/"+tcpClient.getCrtChannel().getThreshold()+") | ";

                clientInput = prompt(roomPrefix+"~\033[1;37m"+tcpClient.getUsername()+" >");

                ConsoleLogger.getTerminal().puts(InfoCmp.Capability.cursor_up);
                ConsoleLogger.getTerminal().puts(InfoCmp.Capability.carriage_return);
                ConsoleLogger.getTerminal().puts(InfoCmp.Capability.clr_eol);
                ConsoleLogger.getTerminal().flush();

                if (clientInput == null) break;
                else if (clientInput.trim().isEmpty()) continue;

                if(clientInput.startsWith(".")) {
                    cmdArgs = clientInput.split(" ");
                    for(CLICommand command : consoleCommands) {
                        if(!cmdArgs[0].substring(1).equalsIgnoreCase(command.getName())) continue;

                        command.execute(Arrays.copyOfRange(cmdArgs, 1, cmdArgs.length));
                    }
                } else {
                    if(tcpClient.getCrtChannel() == null) {
                        ConsoleLogger.info("Join a channel to start chatting, or type .list to see available channels.");
                        continue;
                    }
                    tcpClient.getPacketStream().writeEncryptedPacket(Packet.CHAT_MESSAGE, clientInput.getBytes(StandardCharsets.UTF_8),
                            tcpClient.getCrtChannel().getChannelKey());
                }
            } catch (IOException e) {
                ConsoleLogger.error(reader, "Unable to read your response: " + e.getMessage());
                break;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (GeneralSecurityException | ExecutionException e) {
                ConsoleLogger.error(reader, "Failed to process the response: " + e.getMessage());
                break;
            }
        }
    }

    @SuppressWarnings("BusyWait")
    @Override
    public synchronized void waitForIt(String message) {
        final char[] animChars;
        final Terminal terminal;

        animChars = new char[]{'|', '/', '-', '\\'};
        terminal = ConsoleLogger.getTerminal();

        this.waitMessage = message;

        if (waitThread != null) return;
        isReading = false;

        waitThread = new Thread(() -> {
            int i = 0;

            terminal.writer().print("\033[s");
            terminal.flush();
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    terminal.writer().print("\033[u");
                    terminal.writer().print("\033[2K");

                    terminal.writer().print("\u001B[1;31m" + waitMessage + " " + animChars[i++ % animChars.length] + "\r");
                    terminal.writer().flush();
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            } finally {
                ConsoleLogger.getTerminal().writer().print("\033[u");
                ConsoleLogger.getTerminal().writer().print("\r\u001B[0m\u001B[2K");
                ConsoleLogger.getTerminal().flush();

                waitThread = null;
                isReading = true;
            }
        });
        waitThread.setDaemon(true);
        waitThread.start();
    }

    @Override
    public synchronized void notifyToResume() {
        if(waitThread != null && waitThread.isAlive()) {
            waitThread.interrupt();
        }
    }
}