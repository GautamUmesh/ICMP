package edu.wisc.cs.sdn.vnet.sw;

import java.util.HashMap;
import java.util.Map;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device {
	class TableEntry {
		Iface iface;
		long time;

		TableEntry(Iface iface, long time) {
			this.iface = iface;
			this.time = time;
		}
	}

	Map<MACAddress, TableEntry> table = new HashMap<>();

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host
	 *            hostname for the router
	 */
	public Switch(String host, DumpFile logfile) {
		super(host, logfile);
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

		table.put(etherPacket.getSourceMAC(),
				new TableEntry(inIface, System.currentTimeMillis()));

		TableEntry entry = table.get(etherPacket.getDestinationMAC());
		boolean isBroadcast = entry == null
				|| (System.currentTimeMillis() - entry.time > 15000);

		if (isBroadcast) {
			for (Iface intf : interfaces.values()) {
				if (!intf.equals(inIface)) {
					sendPacket(etherPacket, intf);
				}
			}
		} else {
			sendPacket(etherPacket, entry.iface);
		}
	}
}
