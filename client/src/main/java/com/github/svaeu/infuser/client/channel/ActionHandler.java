package com.github.svaeu.infuser.client.channel;

import com.github.svaeu.infuser.client.TCPClient;
import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.encryption.ECDHEUtil;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Map;

public class ActionHandler {

    private final TCPClient client;

    public ActionHandler(TCPClient client) {
        this.client = client;
    }

    public void onCreateChannel(String channelTitle, int strength, int threshold) {
        final Channel newChannel;

        newChannel = new Channel();
        newChannel.setTitle(channelTitle);
        newChannel.setStrength(strength);
        newChannel.setThreshold(threshold);

        client.getChannels().add(newChannel);
    }

    public void onMetaUpdate(String channelTitle, int strength, int threshold) {
        for(Channel channel : client.getChannels())
            if(channel.getTitle().equalsIgnoreCase(channelTitle)) {
                channel.setStrength(strength);
                channel.setThreshold(threshold);
            }
    }

    public void onRemoveChannel(String channelTitle) {
        client.getChannels().removeIf(channel -> channel.getTitle().equalsIgnoreCase(channelTitle));
    }

    public void onKeyUpdate(String channelTitle, ByteBuffer channelMetaBuffer, byte[] channelID) throws GeneralSecurityException, IOException {
        final Channel updatedChannel;
        final Map.Entry<byte[], byte[]> saltedKeyMap;
        final byte[] bundledKeys, saltedPubKey, encryptedRoomKey;
        final ByteBuffer keyBuffer;

        bundledKeys = new byte[channelMetaBuffer.getInt()];
        channelMetaBuffer.get(bundledKeys);

        keyBuffer = ByteBuffer.wrap(bundledKeys);

        saltedPubKey = new byte[keyBuffer.getInt()];
        keyBuffer.get(saltedPubKey);

        encryptedRoomKey = new byte[keyBuffer.getInt()];
        keyBuffer.get(encryptedRoomKey);

        saltedKeyMap = ECDHEUtil.getDeserializedSaltedKey(saltedPubKey).entrySet().iterator().next();

        updatedChannel = client.getChannels().stream().filter(channel -> channel.getTitle()
                .equalsIgnoreCase(channelTitle)).findFirst().orElse(null);

        if(updatedChannel == null) return;

        updatedChannel.setChannelKey(new SecretKeySpec(client.getPacketListener().getDecryptedDataBytes(encryptedRoomKey,
                ECDHEUtil.deriveAES256Key(ECDHEUtil.getPublicKeyFromBytes(saltedKeyMap.getKey()), updatedChannel.getTrxnKey(),
                        saltedKeyMap.getValue(), "KeyTrxn")), "AES"));
        updatedChannel.setStrength(updatedChannel.getStrength() + 1); //correcting strength as client is expected to be added.

        client.getPacketStream().writeEncryptedPacket(Packet.CHANNEL_UPDATE, ByteBuffer.allocate(8 + channelID.length).putInt(channelID.length)
                .put(channelID).putInt(new byte[0].length).put(new byte[0]).array(), client.getSessionKey());

        client.setCrtChannel(updatedChannel);
    }
}
