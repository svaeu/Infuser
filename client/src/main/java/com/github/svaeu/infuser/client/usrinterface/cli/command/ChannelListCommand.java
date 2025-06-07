package com.github.svaeu.infuser.client.usrinterface.cli.command;

import com.github.svaeu.infuser.client.TCPClient;
import com.github.svaeu.infuser.client.channel.Channel;

import java.io.IOException;

public class ChannelListCommand implements CLICommand {

    private final TCPClient tcpClient;

    public ChannelListCommand(TCPClient tcpClient) {
        this.tcpClient = tcpClient;
    }

    @Override
    public String getDescription() {
        return "List all the available channels to join.";
    }

    @Override
    public String getUsage() {
        return "Usage: .list";
    }

    @Override
    public String getName() {
        return "list";
    }

    @Override
    public void execute(String[] args) throws IOException {
        final StringBuilder channelListings;

        channelListings = new StringBuilder();
        channelListings.append("\033[4m\033[1mACTIVE CHANNELS\033[0m (\033[1;32m").append(tcpClient.getChannels().size())
                .append("\033[0m):\n");

        for(Channel channel : tcpClient.getChannels())
            channelListings.append("• ").append(String.format(channel.toString(),
                    "\033[37m", "\033[0m", "\033[4m", "\033[0m")).append("\n");

        tcpClient.getClientMode().displayMessage(channelListings.toString());
    }
}
