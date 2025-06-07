package com.github.svaeu.infuser.packets;

public enum Packet {

    KEY_ACT(754),
    COMMAND_REQ(625),
    CHANNEL_UPDATE(743),
    CHAT_MESSAGE(834),
    MEDIA_UPLOAD(945),
    SRV_MESSAGE(847),
    AUTH_LOGIN(483),
    REG_ACT(854),
    SRV_FINGERPRINT(278),
    EC_SIGNATURE(632);

    private final int packetID;

    Packet(int packetID) {
        this.packetID = packetID;
    }

    public int getPacketID() {
        return packetID;
    }

    public static Packet fromPacketID(int packetID) {

        for(Packet packet : values())
            if(packet.getPacketID() == packetID)
                return packet;

        return null;
    }
}