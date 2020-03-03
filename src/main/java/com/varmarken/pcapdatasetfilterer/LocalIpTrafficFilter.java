package com.varmarken.pcapdatasetfilterer;

import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.function.Function;

/**
 * A filter that discards all local IP traffic (i.e., all packets that have a source <em>and</em> a destination address
 * that are both in any of the local address spaces are discarded).
 *
 * Also discards packets addressed for the zero network (packets that have 0.0.0.0 and/or 255.255.255.255 as source or
 * destination IP address); note: this part is not yet implemented for IPv6.
 */
public class LocalIpTrafficFilter implements Function<PcapPacket, Boolean> {

    private static final InetAddress INET_ADDR_ZERO_NETWORK;
    private static final InetAddress INET_ADDR_ZERO_NETWORK_BROADCAST;
    static {
        try {
            INET_ADDR_ZERO_NETWORK = InetAddress.getByName("0.0.0.0");
            INET_ADDR_ZERO_NETWORK_BROADCAST = InetAddress.getByName("255.255.255.255");
        } catch (UnknownHostException e) {
            // Should never happen. Rethrow as unchecked to fail early (during class loading).
            throw new RuntimeException("Could not initialize zero network addresses.");
        }
    }

    @Override
    public Boolean apply(PcapPacket pkt) {
        IpPacket ipPkt = pkt.get(IpV4Packet.class);
        if (null == ipPkt) {
            // Not IPv4. IPv6?
            ipPkt = pkt.get(IpV6Packet.class);
        }
        if (null == ipPkt) {
            // Not IP traffic. Include packet.
            return true;
        }
        // Determined that this is IPv4 or IPv6 traffic.
        // Now let's inspect the IP addresses to determine if this is local traffic or Internet traffic.
        InetAddress src = ipPkt.getHeader().getSrcAddr();
        InetAddress dst = ipPkt.getHeader().getDstAddr();
        if (src.isSiteLocalAddress() && dst.isSiteLocalAddress()) {
            // Both endpoints are in local address spaces. Discard packet.
            return false;
        }
        // Note: dst should never equal 0.0.0.0.
        // This is reserved for src. Doesn't hurt to include the check though.
        if (src.equals(INET_ADDR_ZERO_NETWORK) || dst.equals(INET_ADDR_ZERO_NETWORK)) {
            // Discard packets with a 0.0.0.0 source address (e.g., DHCP requests).
            return false;
        }
        // Note: src should never equal 255.255.255.255.
        // This is reserved for dst. Doesn't hurt to include the check though.
        if (dst.equals(INET_ADDR_ZERO_NETWORK_BROADCAST) || src.equals(INET_ADDR_ZERO_NETWORK_BROADCAST)) {
            // Discard broadcast packets (e.g., DHCP requests).
            return false;
        }
        // Packet must have a global IP for one of its endpoints. Include it.
        return true;
    }

}
