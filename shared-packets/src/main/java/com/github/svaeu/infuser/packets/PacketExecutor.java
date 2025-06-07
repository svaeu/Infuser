package com.github.svaeu.infuser.packets;

import com.github.svaeu.infuser.packets.exceptions.MalformedPacketException;
import com.github.svaeu.infuser.packets.exceptions.PacketParsingException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.util.concurrent.ExecutionException;

public abstract class PacketExecutor {

    protected abstract void handleMessagePacket(Packet packet, Object... params) throws GeneralSecurityException, PacketParsingException, IOException, MalformedPacketException;
    protected abstract void handleCommandPacket(Object... params) throws PacketParsingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException;
    protected abstract void handleKeyAction(Object... params) throws GeneralSecurityException, PacketParsingException, IOException;
    protected abstract void handleMediaPacket(Object... params);
    protected abstract void handleChannelUpdate(Object... params) throws PacketParsingException, GeneralSecurityException, MalformedPacketException, IOException, InterruptedException;
    protected abstract void handleAuthenticationAction(Object... params) throws PacketParsingException, GeneralSecurityException, InterruptedException, IOException, ExecutionException;
    protected abstract void handleFingerprintVer(Object... params) throws PacketParsingException, IOException, GeneralSecurityException;
    protected abstract void handleECSignature(Object... params) throws GeneralSecurityException, PacketParsingException, IOException;
    protected abstract void handleRegistrationPacket(Object... params) throws PacketParsingException, GeneralSecurityException, InterruptedException, ExecutionException, IOException;

    public final void exec(Packet packet, Object... data) throws PacketParsingException, GeneralSecurityException, IOException, ExecutionException, InterruptedException, MalformedPacketException {
        switch (packet) {
            case CHAT_MESSAGE -> handleMessagePacket(Packet.CHAT_MESSAGE, data);
            case COMMAND_REQ -> handleCommandPacket(data);
            case KEY_ACT -> handleKeyAction(data);
            case MEDIA_UPLOAD -> handleMediaPacket(data);
            case SRV_FINGERPRINT -> handleFingerprintVer(data);
            case EC_SIGNATURE -> handleECSignature(data);
            case SRV_MESSAGE -> handleMessagePacket(Packet.SRV_MESSAGE, data);
            case REG_ACT -> handleRegistrationPacket(data);
            case CHANNEL_UPDATE -> handleChannelUpdate(data);
            case AUTH_LOGIN -> handleAuthenticationAction(data);
        }
    }

    protected <T> T expectParam(Object[] params, int idx, Class<T> cls) throws PacketParsingException {
        if (params.length <= idx || !cls.isInstance(params[idx]))
            throw new PacketParsingException("Expected parameter " + cls.getSimpleName());

        return cls.cast(params[idx]);
    }
}