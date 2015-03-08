package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.*;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
    /**
     * Routing table for the router
     */
    private RouteTable routeTable;

    /**
     * ARP cache for the router
     */
    private ArpCache arpCache;

    /**
     * Creates a router for a specific host.
     *
     * @param host hostname for the router
     */
    public Router(String host, DumpFile logfile) {
        super(host, logfile);
        this.routeTable = new RouteTable();
        this.arpCache = new ArpCache();
    }

    /**
     * @return routing table for the router
     */
    public RouteTable getRouteTable() {
        return this.routeTable;
    }

    /**
     * Load a new routing table from a file.
     *
     * @param routeTableFile the name of the file containing the routing table
     */
    public void loadRouteTable(String routeTableFile) {
        if (!routeTable.load(routeTableFile, this)) {
            System.err.println("Error setting up routing table from file "
                    + routeTableFile);
            System.exit(1);
        }

        System.out.println("Loaded static route table");
        System.out.println("-------------------------------------------------");
        System.out.print(this.routeTable.toString());
        System.out.println("-------------------------------------------------");
    }

    /**
     * Load a new ARP cache from a file.
     *
     * @param arpCacheFile the name of the file containing the ARP cache
     */
    public void loadArpCache(String arpCacheFile) {
        if (!arpCache.load(arpCacheFile)) {
            System.err.println("Error setting up ARP cache from file "
                    + arpCacheFile);
            System.exit(1);
        }

        System.out.println("Loaded static ARP cache");
        System.out.println("----------------------------------");
        System.out.print(this.arpCache.toString());
        System.out.println("----------------------------------");
    }

    /**
     * Handle an Ethernet packet received on a specific interface.
     *
     * @param etherPacket the Ethernet packet that was received
     * @param inIface     the interface on which the packet was received
     */
    public void handlePacket(Ethernet etherPacket, Iface inIface) {
        System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));

        /********************************************************************/
        /* TODO: Handle packets                                             */

        switch (etherPacket.getEtherType()) {
            case Ethernet.TYPE_IPv4:
                this.handleIpPacket(etherPacket, inIface);
                break;
            case Ethernet.TYPE_ARP:
                handleArpPacket(etherPacket, inIface);
                break;
        }

        /********************************************************************/
    }

    private void handleArpPacket(Ethernet etherPacket, Iface inIface) {
        ARP arpPacket = (ARP) etherPacket.getPayload();
        switch (arpPacket.getOpCode()) {
            case ARP.OP_REQUEST:
                handleArpRequest(etherPacket, inIface);
                break;
            case ARP.OP_REPLY:
                handleArpReply(etherPacket);
        }
    }

    private void handleArpReply(Ethernet etherPacket)
    {
        ARP arpPacket = (ARP) etherPacket.getPayload();
    }

    private void handleArpRequest(Ethernet originalEtherPacket, Iface inIface) {
        ARP originalArpPacket = (ARP) originalEtherPacket.getPayload();
        int targetIp = ByteBuffer.wrap(originalArpPacket.getTargetProtocolAddress()).getInt();
        if (inIface.getIpAddress() != targetIp) {
            return;
        }
        Ethernet ethernetReply = constructArpPacket(
                originalEtherPacket.getSourceMACAddress(),
                ARP.OP_REPLY,
                originalArpPacket.getSenderHardwareAddress(),
                originalArpPacket.getTargetProtocolAddress(),
                inIface);

        sendPacket(ethernetReply, inIface);
    }

    private void sendArpRequest(int targetIp, Iface inIface) {
        byte[] broadcast = new byte[6];
        Arrays.fill(broadcast, (byte) 0xFF);
        byte[] zeroHw = new byte[6];
        Arrays.fill(broadcast, (byte) 0);
        byte [] ip = IPv4.toIPv4AddressBytes(targetIp);
        Ethernet ethernetPacket = constructArpPacket(
                broadcast,
                ARP.OP_REQUEST,
                zeroHw,
                ip,
                inIface);
        sendPacket(ethernetPacket, inIface);
    }

    private Ethernet constructArpPacket(byte[] dstMacAddr, short opCode, byte[] targetHwAddr,
                                        byte[] targetProtoAddr, Iface inIface) {
        Ethernet ethernetReply = new Ethernet();
        ethernetReply.setEtherType(Ethernet.TYPE_ARP);
        ethernetReply.setSourceMACAddress(inIface.getMacAddress().toBytes());
        ethernetReply.setDestinationMACAddress(dstMacAddr);

        ARP arpReply = new ARP();
        arpReply.setHardwareType(ARP.HW_TYPE_ETHERNET);
        arpReply.setProtocolType(ARP.PROTO_TYPE_IP);
        arpReply.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
        arpReply.setProtocolAddressLength((byte) 4);
        arpReply.setOpCode(ARP.OP_REPLY);
        arpReply.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
        arpReply.setSenderProtocolAddress(inIface.getIpAddress());
        arpReply.setTargetHardwareAddress(targetHwAddr);
        arpReply.setTargetProtocolAddress(targetProtoAddr);
        ethernetReply.setPayload(arpReply);
        return ethernetReply;
    }

    private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
        final Ethernet originalEtherPacket = (Ethernet) etherPacket.clone();
        // Make sure it's an IP packet
        if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
            return;
        }

        // Get IP header
        IPv4 ipPacket = (IPv4) etherPacket.getPayload();
        System.out.println("Handle IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum) {
            return;
        }

        // Check TTL
        ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));
        if (0 == ipPacket.getTtl()) {
            sendTimeExceededPacket(originalEtherPacket, inIface);
            return;
        }

        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();

        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values()) {
            if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
                byte protocol = ipPacket.getProtocol();
                if (protocol == IPv4.PROTOCOL_TCP || protocol == IPv4.PROTOCOL_UDP) {
                    sendDestinationPortUnreachablePacket(originalEtherPacket, inIface);
                } else if (protocol == IPv4.PROTOCOL_ICMP) {
                    ICMP icmpPacket = (ICMP) ipPacket.getPayload();
                    if (icmpPacket.getIcmpType() == ICMP.TYPE_ECHO_REQUEST) {
                        sendEchoReplyPacket(originalEtherPacket, inIface);
                    }
                }
                return;
            }
        }

        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface, originalEtherPacket);
    }

    private void sendEchoReplyPacket(Ethernet originalPacket, Iface inIface) {
        IPv4 originalIPv4 = (IPv4) originalPacket.getPayload();

        Ethernet ether = new Ethernet();
        ether.setEtherType(Ethernet.TYPE_IPv4);
        ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
        byte[] dstMac = getDestinationMacOfNextHop(originalIPv4);
        if (null == dstMac) {
            System.err.println("Null dstMac");
            return;
        }
        ether.setDestinationMACAddress(dstMac);

        IPv4 ip = new IPv4();
        ip.setTtl((byte) 64);
        ip.setProtocol(IPv4.PROTOCOL_ICMP);
        ip.setSourceAddress(originalIPv4.getDestinationAddress());
        ip.setDestinationAddress(originalIPv4.getSourceAddress());

        ICMP icmp = new ICMP();
        icmp.setIcmpType((byte) 0);
        icmp.setIcmpCode((byte) 0);

        ICMP originalIcmp = (ICMP) originalIPv4.getPayload();
        Data data = new Data(originalIcmp.getPayload().serialize());

        ether.setPayload(ip);
        ip.setPayload(icmp);
        icmp.setPayload(data);
        sendPacket(ether, inIface);
    }

    private void sendTimeExceededPacket(Ethernet originalPacket, Iface inIface) {
        sendICMPPacketHelper(originalPacket, inIface, (byte) 11, (byte) 0);
    }

    private void sendDestinationNetUnreachablePacket(Ethernet originalPacket, Iface inIface) {
        sendICMPPacketHelper(originalPacket, inIface, (byte) 3, (byte) 0);
    }

    private void sendDestinationHostUnreachablePacket(Ethernet originalPacket, Iface inIface) {
        sendICMPPacketHelper(originalPacket, inIface, (byte) 3, (byte) 1);
    }

    private void sendDestinationPortUnreachablePacket(Ethernet originalPacket, Iface inIface) {
        sendICMPPacketHelper(originalPacket, inIface, (byte) 3, (byte) 3);
    }

    private void sendICMPPacketHelper(Ethernet originalPacket, Iface inIface, byte type, byte code) {
        IPv4 originalIPv4 = (IPv4) originalPacket.getPayload();

        Ethernet ether = new Ethernet();
        ether.setEtherType(Ethernet.TYPE_IPv4);
        ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
        byte[] dstMac = getDestinationMacOfNextHop(originalIPv4);
        if (null == dstMac) {
            System.err.println("Null dstMac");
            return;
        }
        ether.setDestinationMACAddress(dstMac);

        IPv4 ip = new IPv4();
        ip.setTtl((byte) 64);
        ip.setProtocol(IPv4.PROTOCOL_ICMP);
        ip.setSourceAddress(inIface.getIpAddress());
        ip.setDestinationAddress(originalIPv4.getSourceAddress());

        ICMP icmp = new ICMP();
        icmp.setIcmpType(type);
        icmp.setIcmpCode(code);

        int headerLenBytes = originalIPv4.getHeaderLength() * 4;
        byte[] dataBytes = new byte[4 + headerLenBytes + 8];
        Arrays.fill(dataBytes, 0, 4, (byte) 0);
        byte[] originalIPv4Bytes = originalIPv4.serialize();
        for (int i = 0; i < headerLenBytes + 8; i++) {
            dataBytes[i + 4] = originalIPv4Bytes[i];
        }
        Data data = new Data(dataBytes);

        ether.setPayload(ip);
        ip.setPayload(icmp);
        icmp.setPayload(data);
        sendPacket(ether, inIface);
    }

    private byte[] getDestinationMacOfNextHop(IPv4 ipPacket) {
        int dstAddr = ipPacket.getSourceAddress();
        RouteEntry bestMatch = routeTable.lookup(dstAddr);
        if (null == bestMatch) {
            return null;
        }
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop) {
            nextHop = dstAddr;
        }
        ArpEntry arpEntry = arpCache.lookup(nextHop);
        if (null == arpEntry) {
            return null;
        }
        return arpEntry.getMac().toBytes();
    }

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface, Ethernet originalPacket) {
        // Make sure it's an IP packet
        if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
            return;
        }
        System.out.println("Forward IP packet");

        // Get IP header
        IPv4 ipPacket = (IPv4) etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (null == bestMatch) {
            sendDestinationNetUnreachablePacket(originalPacket, inIface);
            return;
        }

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface) {
            return;
        }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop) {
            nextHop = dstAddr;
        }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry) {
            sendArpRequest(nextHop, inIface);
            sendDestinationHostUnreachablePacket(etherPacket, inIface);
            return;
        }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

        this.sendPacket(etherPacket, outIface);
    }
}
