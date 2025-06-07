package com.github.svaeu.infuser.packets;

import java.util.HashSet;
import java.util.Set;

public class PacketProcessor {

    private final PacketExecutor packetExecutor;

    private final Set<Packet> blockedPackets = new HashSet<>();

    public PacketProcessor(PacketExecutor packetExecutor) {
        this.packetExecutor = packetExecutor;
    }

    public PacketExecutor getExecutor() {
        return packetExecutor;
    }

    public Set<Packet> getBlockedPackets() {
        return blockedPackets;
    }
}