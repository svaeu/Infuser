package com.github.svaeu.infuser.server.util;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class IPFilter {
    public enum ListType { WHITELISTED, BLACKLISTED }

    private final Map<ListType, Set<String>> typeLists;

    public IPFilter() {
        typeLists = new EnumMap<>(ListType.class);
        typeLists.put(ListType.WHITELISTED, ConcurrentHashMap.newKeySet());
        typeLists.put(ListType.BLACKLISTED, ConcurrentHashMap.newKeySet());
    }

    public Set<String> getWhitelist() {
        return Collections.unmodifiableSet(typeLists.get(ListType.WHITELISTED));
    }

    public Set<String> getBlacklist() {
        return Collections.unmodifiableSet(typeLists.get(ListType.BLACKLISTED));
    }

    public void whitelist(String ip) { addIP(ListType.WHITELISTED, ip); }
    public void unwhitelist(String ip) { removeIP(ListType.WHITELISTED, ip); }
    public boolean isWhitelisted(String ip) {
        return containsIP(ListType.WHITELISTED, ip);
    }

    public void blacklist(String ip) { addIP(ListType.BLACKLISTED, ip); }
    public void unblacklist(String ip) { removeIP(ListType.BLACKLISTED, ip); }
    public boolean isBlacklisted(String ip) {
        return containsIP(ListType.BLACKLISTED, ip);
    }

    public void addIP(ListType type, String ip) {
        requireNonNull(ip);
        typeLists.get(type).add(ip);
    }

    public void removeIP(ListType type, String ip) {
        requireNonNull(ip);
        typeLists.get(type).remove(ip);
    }

    public boolean containsIP(ListType type, String ip) {
        requireNonNull(ip);
        return typeLists.get(type).contains(ip);
    }

    private static void requireNonNull(Object obj) {
        if (obj == null) throw new NullPointerException("IP cannot be null.");
    }
}