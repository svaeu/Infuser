package com.github.svaeu.infuser.client.channel;

import com.github.svaeu.infuser.client.TCPClient;
import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.encryption.ECDHEUtil;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.Optional;

public class ActionHandler {

    private final TCPClient client;

    public ActionHandler(TCPClient client) {
        this.client = client;
    }

    public void createChannel(String title, int strength, int threshold) {
        final Channel channel;

        channel = Channel.builder()
                .title(title)
                .strength(strength)
                .threshold(threshold)
                .build();

        client.getChannels().add(channel);
    }

    public void updateChannelMeta(String title, int strength, int threshold) {
        findChannelByTitle(title)
                .map(channel -> {
                    channel.setStrength(strength);
                    channel.setThreshold(threshold);
                    return true;
                });
    }

    public void removeChannel(String channelTitle) {
        client.getChannels().removeIf(
                channel -> channel.getTitle().equalsIgnoreCase(channelTitle)
        );
    }

    public void onKeyUpdate(String title, ByteBuffer channelMetaBuffer, byte[] channelID) throws GeneralSecurityException, IOException {
        final byte[] bundledKeys, saltedPubKey, encryptedRoomKey;
        final ByteBuffer keyBuffer, updatePacket;
        final Optional<Channel> channelOpt;
        final Channel updatedChannel;

        bundledKeys = new byte[channelMetaBuffer.getInt()];
        channelMetaBuffer.get(bundledKeys);

        keyBuffer = ByteBuffer.wrap(bundledKeys);

        saltedPubKey = new byte[keyBuffer.getInt()];
        keyBuffer.get(saltedPubKey);

        encryptedRoomKey = new byte[keyBuffer.getInt()];
        keyBuffer.get(encryptedRoomKey);

        channelOpt = findChannelByTitle(title);
        if(channelOpt.isEmpty()) return;

        updatedChannel = channelOpt.get();

        updatedChannel.setChannelKey(
                deriveChannelKey(
                        saltedPubKey, encryptedRoomKey, updatedChannel)
        );
        updatedChannel.setStrength(updatedChannel.getStrength() + 1);

        notifyChannelUpdate(channelID);
        client.setCrtChannel(updatedChannel);
    }

    private SecretKeySpec deriveChannelKey(byte[] saltedPubKey, byte[] encryptedRoomKey, Channel updatedChannel) throws GeneralSecurityException {
        final Map.Entry<byte[], byte[]> saltedKeyMap;
        final byte[] decryptedKey;

        saltedKeyMap = ECDHEUtil
                .getDeserializedSaltedKey(saltedPubKey)
                .entrySet()
                .iterator()
                .next();

        decryptedKey = client.getPacketListener().getDecryptedDataBytes(
                encryptedRoomKey,
                ECDHEUtil.deriveAES256Key(
                        ECDHEUtil.getPublicKeyFromBytes(saltedKeyMap.getKey()),
                        updatedChannel.getTrxnKey(),
                        saltedKeyMap.getValue(),
                        "KeyTrxn"
                )
        );
        return new SecretKeySpec(decryptedKey, client.CIPHER_ALGO);
    }

    private void notifyChannelUpdate(byte[] channelID) throws GeneralSecurityException, IOException {
        final ByteBuffer updateBuffer;

        updateBuffer = ByteBuffer.allocate(8 + channelID.length)
                .putInt(channelID.length)
                .put(channelID)
                .putInt(new byte[0].length)
                .put(new byte[0]);

        client.getPacketStream().writeEncryptedPacket(
                Packet.CHANNEL_UPDATE,
                updateBuffer.array(),
                client.getSessionKey()
        );
    }

    private Optional<Channel> findChannelByTitle(String title) {
        return client.getChannels().stream()
                .filter(channel -> channel.getTitle().equalsIgnoreCase(title))
                .findFirst();
    }
}
