package com.github.svaeu.infuser.client.usrinterface.cli.command;

import java.io.IOException;
import java.security.GeneralSecurityException;

public interface CLICommand {
    String getDescription();
    String getUsage();
    String getName();

    void execute(String[] args) throws GeneralSecurityException,
            IOException,
            InterruptedException;
}
