extern crate pnet;

mod packet;
mod frame;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet};
use pnet::packet::ethernet::{EthernetPacket};

use std::vec::Vec;

use std::ops::Deref;

fn main() {
	let packet = packet::DhcpPacket {
			packet_type: packet::PacketType::Discover,
			xid: 0,
			seconds: 0,
			client_addr: None,
			your_addr: None,
			server_addr: None,
			gateway_addr: None,
			client_hwaddr: packet::EthernetAddr([0x33; 6]),
			options: vec![
				packet::DhcpOption::SubnetMask(packet::IpAddr([255, 255, 255, 0]))
				],
			flags: vec![packet::DhcpFlags::Broadcast]
		};

	let interfaces = datalink::interfaces();
	let interface = interfaces.into_iter().filter(|iface: &NetworkInterface | iface.name == "eth0").next().unwrap();
	let mac = interface.mac.unwrap();

	let (mut tx, _) = match datalink::channel(&interface, Default::default()) {
		Ok(Ethernet(tx, rx)) => (tx, rx),
		Ok(_) => panic!("Unhandles channel type!"),
		Err(e) => panic!("An error occured while creating ethernet channel: {}", e)
	};

	println!("{:?}", packet);
	println!("{:?}", mac);

	let payload = packet.serialize();
	let udp = frame::UDP { src: 68, dst: 67, payload: payload.as_slice()}.serialize();
	let ip = frame::IPv4Packet { src: frame::IPv4Addr([0, 0, 0, 0]), dst: frame::IPv4Addr([255, 255, 255, 255]), ttl: 64, protocol: 17, payload: udp.deref()}.serialize();
	let ethernet = frame::Ethernet{src: frame::EthernetAddr([mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]), dst: frame::EthernetAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), eth_type: 0x0800, payload: ip.deref()}.serialize();

	tx.send_to(ethernet.deref(), None);
}
