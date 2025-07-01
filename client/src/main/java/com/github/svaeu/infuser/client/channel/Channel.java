package com.github.svaeu.infuser.client.channel;

import lombok.Getter;
import lombok.Setter;

import javax.crypto.SecretKey;
import java.security.PrivateKey;

@Setter
@Getter
public class Channel {

    private String title;
    private int strength, threshold;

    private SecretKey channelKey;
    private PrivateKey trxnKey;

    private Channel() {}

    public static ChannelBuilder builder() {
        return new ChannelBuilder();
    }

    public static class ChannelBuilder {
        private final Channel channel;

        public ChannelBuilder() {
            this.channel = new Channel();
        }

        public ChannelBuilder title(String title) {
            channel.setTitle(title);
            return this;
        }

        public ChannelBuilder strength(int strength) {
            channel.setStrength(strength);
            return this;
        }

        public ChannelBuilder threshold(int threshold) {
            channel.setThreshold(threshold);
            return this;
        }

        public Channel build() {
            return channel;
        }
    }

    @Override
    public String toString() {
        return "%s#"+title+"%s | Members Online: [%s"+strength+"%s/"+threshold+"]";
    }
}
