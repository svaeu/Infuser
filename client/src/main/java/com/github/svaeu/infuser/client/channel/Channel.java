package com.github.svaeu.infuser.client.channel;

import javax.crypto.SecretKey;
import java.security.PrivateKey;

public class Channel {

    private String title;
    private int strength, threshold;

    private SecretKey channelKey;
    private PrivateKey trxnKey;

    public int getThreshold() {
        return threshold;
    }

    public int getStrength() {
        return strength;
    }

    public String getTitle() {
        return title;
    }

    public void setStrength(int strength) {
        this.strength = strength;
    }

    public void setThreshold(int threshold) {
        this.threshold = threshold;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public PrivateKey getTrxnKey() {
        return trxnKey;
    }

    public void setTrxnKey(PrivateKey trxnKey) {
        this.trxnKey = trxnKey;
    }

    public SecretKey getChannelKey() {
        return channelKey;
    }

    public void setChannelKey(SecretKey channelKey) {
        this.channelKey = channelKey;
    }

    @Override
    public String toString() {
        return "%s#"+title+"%s | Members Online: [%s"+strength+"%s/"+threshold+"]";
    }
}
