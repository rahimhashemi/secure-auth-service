package com.simpath.app.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class ClientAddressResolver {
    private final Set<String> trustedProxies;
    public ClientAddressResolver(@Value("${app.security.trusted-proxies:}") String proxies) {
        trustedProxies = Arrays.stream(proxies.split(",")).map(String::trim).filter(s -> !s.isEmpty())
                .map(ClientAddressResolver::literal).collect(Collectors.toUnmodifiableSet());
    }
    public String resolve(HttpServletRequest request) {
        String remote = request.getRemoteAddr();
        String peer;
        try { peer = literal(remote); } catch (IllegalArgumentException ex) { return remote; }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (!trustedProxies.contains(peer) || forwarded == null) return peer;
        // The single trusted ingress must overwrite this header, not append a chain.
        try { return literal(forwarded.trim()); } catch (IllegalArgumentException ex) { return peer; }
    }
    private static String literal(String value) {
        if (!value.matches("[0-9a-fA-F:.]+") || (!value.contains(":") && value.chars().filter(c -> c == '.').count() != 3)) {
            throw new IllegalArgumentException("Expected a literal IP address");
        }
        try { return InetAddress.getByName(value).getHostAddress(); }
        catch (UnknownHostException ex) { throw new IllegalArgumentException("Invalid IP address", ex); }
    }
}
