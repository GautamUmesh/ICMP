package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.*;

import java.nio.ByteBuffer;
import java.util.*;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {

	private Timer scheduler;

	/**
	 * Routing table for the router
	 */
	private RouteTable routeTable;

	/**
	 * ARP cache for the router
	 */
	private ArpCache arpCache;

	public static final byte[] BROADCAST = new byte[6];
	public static final int RIP_BROADCAST_IP = IPv4.toIPv4Address("224.0.0.9");
	final Map<String, RIPInternalEntry> ripInternalMap = Collections
			.synchronizedMap(new HashMap<String, RIPInternalEntry>());
	final Set<Integer> arpAttempt = Collections
			.synchronizedSet(new HashSet<Integer>());
	final Map<Integer, List<Ethernet>> packetQueue = Collections
			.synchronizedMap(new HashMap<Integer, List<Ethernet>>());

	class InterfacePair {
		public Iface inIface;
		public Iface outIface;

		public InterfacePair(Iface inIface, Iface outIface) {
			this.inIface = inIface;
			this.outIface = outIface;
		}
	}

	final Map<Ethernet, InterfacePair> packetInterfaceMap = Collections
			.synchronizedMap(new HashMap<Ethernet, InterfacePair>());

	/**
	 * Creates a router for a specific host.
	 *
	 * @param host
	 *            hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		scheduler = new Timer();
		Arrays.fill(BROADCAST, (byte) 0xFF);
	}

	class RIPInternalEntry {
		int metric;
		long timestamp;

		public RIPInternalEntry(int metric, long timestamp) {
			this.metric = metric;
			this.timestamp = timestamp;
		}
	}

	class RIPHeartBeatTask extends TimerTask {
		@Override
		public void run() {
			sendUnsolicitedRipRequests();
		}
	}

	private void sendUnsolicitedRipRequests() {
		for (Iface i : interfaces.values()) {
			Ethernet packet = constructRipUnsolicitedResponse(i);
			sendPacket(packet, i);
		}
	}

	class RouterEntryPurgeTask extends TimerTask {
		@Override
		public void run() {
			long currentTime = System.currentTimeMillis();
			boolean modified = false;
			synchronized (ripInternalMap) {
				Iterator<Map.Entry<String, RIPInternalEntry>> it = ripInternalMap
						.entrySet().iterator();
				while (it.hasNext()) {
					Map.Entry<String, RIPInternalEntry> entry = it.next();
					long ts = entry.getValue().timestamp;
					if (ts != -1 && ts + 30 * 1000 < currentTime) {
						String seg[] = entry.getKey().split(",");
						int na = Integer.parseInt(seg[0]);
						int mask = Integer.parseInt(seg[1]);
						it.remove();
						routeTable.remove(na, mask);
						modified = true;
					}
				}
			}
			if (modified) {
				sendUnsolicitedRipRequests();
			}
		}
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
	 * @param routeTableFile
	 *            the name of the file containing the routing table
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
	 * @param arpCacheFile
	 *            the name of the file containing the ARP cache
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
	 * @param etherPacket
	 *            the Ethernet packet that was received
	 * @param inIface
	 *            the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: "
				+ etherPacket.toString().replace("\n", "\n\t"));
		for (Iface di : interfaces.values()) {
			arpCache.insert(di.getMacAddress(), di.getIpAddress());
		}

		switch (etherPacket.getEtherType()) {
		case Ethernet.TYPE_IPv4:
			if (isRipPacket(etherPacket)) {
				handleRipPacket(etherPacket, inIface);
			} else {
				this.handleIpPacket(etherPacket, inIface);
			}
			break;
		case Ethernet.TYPE_ARP:
			handleArpPacket(etherPacket, inIface);
			break;
		}
	}

	private void handleRipPacket(Ethernet etherPacket, Iface iface) {
		IPv4 ip = (IPv4) etherPacket.getPayload();
		UDP udp = (UDP) ip.getPayload();
		RIPv2 rip = (RIPv2) udp.getPayload();
		if (rip.getCommand() == RIPv2.COMMAND_RESPONSE) {
			handleRipResponse(rip, iface);
		} else if (rip.getCommand() == RIPv2.COMMAND_REQUEST) {
			handleRipRequest(ip.getSourceAddress(), iface);
		}
	}

	private void handleRipRequest(int ip, Iface iface) {
		Ethernet ether = constructRipSolicitedResponse(iface, ip, BROADCAST);
		byte[] dstMac = getDestinationMacOfNextHop(ip);
		if (null == dstMac) {
			sendPacketLater(ether, iface, iface);
		} else {
			ether.setDestinationMACAddress(dstMac);
			sendPacket(ether, iface);
		}
	}

	private void handleRipResponse(RIPv2 rip, Iface iface) {
		boolean modified = false;
		for (RIPv2Entry entry : rip.getEntries()) {
			int na = entry.getAddress();
			int mask = entry.getSubnetMask();
			int metric = entry.getMetric() + 1;
			int ip = entry.getNextHopAddress();
			String hashKey = getHashKey(na, mask);
			boolean shouldAdd = !(ripInternalMap.containsKey(hashKey) && metric >= ripInternalMap
					.get(hashKey).metric);
			if (shouldAdd) {
				if (routeTable.find(na, mask) != null) {
					routeTable.remove(na, mask);
				}
				routeTable.insert(na, ip, mask, iface);
				ripInternalMap
						.put(hashKey,
								new RIPInternalEntry(metric, System
										.currentTimeMillis()));
				modified = true;
			}
		}
		if (modified) {
			sendUnsolicitedRipRequests();
		}
	}

	private boolean isRipPacket(Ethernet ethernet) {
		if (ethernet.getEtherType() != Ethernet.TYPE_IPv4) {
			return false;
		}

		IPv4 ip = (IPv4) ethernet.getPayload();
		if (!(ip.getPayload() instanceof UDP)) {
			return false;
		}

		UDP udp = (UDP) ip.getPayload();
		if (udp.getDestinationPort() != UDP.RIP_PORT) {
			return false;
		}
		return true;
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

	private void handleArpReply(Ethernet etherPacket) {
		ARP arpPacket = (ARP) etherPacket.getPayload();
		int ip = IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress());
		MACAddress mac = new MACAddress(arpPacket.getSenderHardwareAddress());
		arpCache.insert(mac, ip);
		sendPendingPackets(mac.toBytes(), ip);
	}

	void sendPendingPackets(byte[] mac, int ip) {
		synchronized (packetQueue) {
			arpAttempt.remove(ip);
			List<Ethernet> ipPacketQueue = packetQueue.get(ip);
			packetQueue.remove(ip);
			if (ipPacketQueue != null) {
				for (Ethernet packet : ipPacketQueue) {
					Iface oface = packetInterfaceMap.get(packet).outIface;
					packet.setDestinationMACAddress(mac);
					sendPacket(packet, oface);
					packetInterfaceMap.remove(packet);
				}
			}
		}
	}

	private void handleArpRequest(Ethernet originalEtherPacket, Iface inIface) {
		ARP originalArpPacket = (ARP) originalEtherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(
				originalArpPacket.getTargetProtocolAddress()).getInt();
		if (inIface.getIpAddress() != targetIp) {
			return;
		}
		Ethernet ethernetReply = constructArpPacket(
				originalEtherPacket.getSourceMACAddress(), ARP.OP_REPLY,
				originalArpPacket.getSenderHardwareAddress(),
				originalArpPacket.getSenderProtocolAddress(), inIface);

		sendPacket(ethernetReply, inIface);
	}

	private void sendArpRequest(int targetIp, Iface oface) {
		byte[] zeroHw = new byte[6];
		Arrays.fill(zeroHw, (byte) 0);
		byte[] ip = IPv4.toIPv4AddressBytes(targetIp);
		Ethernet ethernetPacket = constructArpPacket(BROADCAST, ARP.OP_REQUEST,
				zeroHw, ip, oface);
		sendPacket(ethernetPacket, oface);
	}

	private Ethernet constructArpPacket(byte[] dstMacAddr, short opCode,
			byte[] targetHwAddr, byte[] targetProtoAddr, Iface inIface) {
		Ethernet ethernetReply = new Ethernet();
		ethernetReply.setEtherType(Ethernet.TYPE_ARP);
		ethernetReply.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ethernetReply.setDestinationMACAddress(dstMacAddr);

		ARP arpReply = new ARP();
		arpReply.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arpReply.setProtocolType(ARP.PROTO_TYPE_IP);
		arpReply.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		arpReply.setProtocolAddressLength((byte) 4);
		arpReply.setOpCode(opCode);
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
				if (protocol == IPv4.PROTOCOL_TCP
						|| protocol == IPv4.PROTOCOL_UDP) {
					sendDestinationPortUnreachablePacket(originalEtherPacket,
							inIface);
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

		byte[] dstMac = getDestinationMacOfNextHop(originalIPv4
				.getSourceAddress());
		if (null == dstMac) {
			sendPacketLater(ether, inIface, inIface);
			return;
		}
		ether.setDestinationMACAddress(dstMac);
		sendPacket(ether, inIface);
	}

	private void sendTimeExceededPacket(Ethernet originalPacket, Iface inIface) {
		sendICMPPacketHelper(originalPacket, inIface, (byte) 11, (byte) 0);
	}

	private void sendDestinationNetUnreachablePacket(Ethernet originalPacket,
			Iface inIface) {
		sendICMPPacketHelper(originalPacket, inIface, (byte) 3, (byte) 0);
	}

	private void sendDestinationHostUnreachablePacket(Ethernet originalPacket,
			Iface inIface) {
		sendICMPPacketHelper(originalPacket, inIface, (byte) 3, (byte) 1);
	}

	private void sendDestinationPortUnreachablePacket(Ethernet originalPacket,
			Iface inIface) {
		sendICMPPacketHelper(originalPacket, inIface, (byte) 3, (byte) 3);
	}

	private void sendICMPPacketHelper(Ethernet originalPacket, Iface inIface,
			byte type, byte code) {
		IPv4 originalIPv4 = (IPv4) originalPacket.getPayload();

		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());

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

		byte[] dstMac = getDestinationMacOfNextHop(originalIPv4
				.getSourceAddress());
		if (null == dstMac) {
			sendPacketLater(ether, inIface, inIface);
			return;
		}
		ether.setDestinationMACAddress(dstMac);
		sendPacket(ether, inIface);
	}

	private byte[] getDestinationMacOfNextHop(int dstAddr) {
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

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface,
			Ethernet originalPacket) {
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
			sendPacketLater(etherPacket, inIface, outIface);
			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
		sendPacket(etherPacket, outIface);
	}

	private void sendPacketLater(Ethernet originalPacket, Iface inIface,
			Iface outIface) {
		IPv4 ipv4 = (IPv4) originalPacket.getPayload();
                RouteEntry bestMatch = this.routeTable.lookup(ipv4.getDestinationAddress());
		int ip = bestMatch.getGatewayAddress();
		if (0 == ip) {
			ip = ipv4.getDestinationAddress();
		}
		originalPacket.setDestinationMACAddress(BROADCAST);
		synchronized (packetQueue) {
			if (!packetQueue.containsKey(ip)) {
				packetQueue.put(ip, new ArrayList<Ethernet>());
			}
			List<Ethernet> ipPacketQueue = packetQueue.get(ip);
			ipPacketQueue.add(originalPacket);
			packetInterfaceMap.put(originalPacket, new InterfacePair(inIface,
					outIface));

			if (!arpAttempt.contains(ip)) {
				TimerTask arpRequester = new ArpTimer(ip, outIface);
				scheduler.schedule(arpRequester, 0, 1000);
			}
		}
	}

	public void ripInitialize() {
		for (Iface di : interfaces.values()) {
			int mask = di.getSubnetMask();
			int na = getNetworkAddress(di.getIpAddress(), mask);
			routeTable.insert(na, 0, mask, di);
			ripInternalMap.put(getHashKey(na, mask),
					new RIPInternalEntry(0, -1));
			sendPacket(constructRipRequest(di), di);
		}
		scheduler.schedule(new RIPHeartBeatTask(), 0, 10 * 1000);
		scheduler.schedule(new RouterEntryPurgeTask(), 0, 1000);
	}

	private String getHashKey(int na, int mask) {
		return na + "," + mask;
	}

	private int getNetworkAddress(int ip, int mask) {
		return ip & mask;
	}

	private Ethernet constructRipRequest(Iface iface) {
		return constructRipPacket(iface, RIP_BROADCAST_IP, BROADCAST,
				RIPv2.COMMAND_REQUEST);
	}

	private Ethernet constructRipSolicitedResponse(Iface iface, int destIp,
			byte destMac[]) {
		return constructRipPacket(iface, destIp, destMac,
				RIPv2.COMMAND_RESPONSE);
	}

	private Ethernet constructRipUnsolicitedResponse(Iface iface) {
		return constructRipPacket(iface, RIP_BROADCAST_IP, BROADCAST,
				RIPv2.COMMAND_RESPONSE);
	}

	private Ethernet constructRipPacket(Iface iface, int destIp,
			byte[] destMac, byte command) {
		Ethernet ethernet = new Ethernet();
		ethernet.setEtherType(Ethernet.TYPE_IPv4);
		ethernet.setDestinationMACAddress(destMac);
		ethernet.setSourceMACAddress(iface.getMacAddress().toBytes());

		UDP udp = new UDP();
		udp.setDestinationPort(UDP.RIP_PORT);
		udp.setSourcePort(UDP.RIP_PORT);

		IPv4 ip = new IPv4();
		ip.setDestinationAddress(destIp);
		ip.setSourceAddress(iface.getIpAddress());
		ip.setTtl((byte) 16);
		ip.setProtocol(IPv4.PROTOCOL_UDP);

		RIPv2 rip = constructRipv2Packet(command, iface.getIpAddress());

		udp.setPayload(rip);
		ip.setPayload(udp);
		ethernet.setPayload(ip);
		return ethernet;
	}

	private RIPv2 constructRipv2Packet(byte command, int ifaceIp) {
		RIPv2 rip = new RIPv2();
		rip.setCommand(command);
		if (command == RIPv2.COMMAND_RESPONSE) {
			synchronized (routeTable.entries) {
				for (RouteEntry entry : routeTable.entries) {
					int ip = entry.getDestinationAddress();
					int mask = entry.getMaskAddress();
					String hashKey = getHashKey(ip, mask);
					RIPv2Entry riPv2Entry = new RIPv2Entry(ip, mask,
							ripInternalMap.get(hashKey).metric);
					riPv2Entry.setNextHopAddress(ifaceIp);
					rip.addEntry(riPv2Entry);
				}
			}
		}
		return rip;
	}

	void dropPackets(int ip) {
		synchronized (packetQueue) {
			arpAttempt.remove(ip);
			List<Ethernet> ipPacketQueue = packetQueue.get(ip);
			packetQueue.remove(ip);
			if (ipPacketQueue != null) {
				for (Ethernet packet : ipPacketQueue) {
					sendDestinationHostUnreachablePacket(packet,
							packetInterfaceMap.get(packet).inIface);
					packetInterfaceMap.remove(packet);
				}
			}
		}
	}

	class ArpTimer extends TimerTask {
		int numAttempts = 3;
		final Iface oface;
		final int ip;

		public ArpTimer(int ip, Iface oface) {
			this.ip = ip;
			this.oface = oface;
		}

		@Override
		public void run() {
			ArpEntry entry = arpCache.lookup(ip);
			if (entry != null) {
				cancel();
				return;
			} else {
				if (numAttempts == 0) {
					dropPackets(ip);
					cancel();
				} else {
					sendArpRequest(ip, oface);
				}
			}
			numAttempts--;
		}
	}
}
