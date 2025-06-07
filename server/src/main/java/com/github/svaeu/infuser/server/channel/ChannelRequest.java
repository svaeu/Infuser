package com.github.svaeu.infuser.server.channel;

import com.github.svaeu.infuser.server.client.ClientEntity;

public record ChannelRequest(ClientEntity seekingClient, VirtualRoom vr) {}
