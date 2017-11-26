#[macro_use]
extern crate serde_derive;

extern crate pnet;
extern crate time;

mod frame;
mod lease;
mod packet;
mod pool;
mod serialize;
mod allocator;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel;

use std::ops::Deref;

use frame::ethernet::{Ethernet, EthernetAddr};
use frame::ip4::{IPv4Packet, IPv4Addr};
use frame::udp::UDP;

fn decode_dhcp(rec: &[u8]) -> Result<packet::DhcpPacket<EthernetAddr>, String> {
	let tmp = serialize::deserialize::<Ethernet<IPv4Packet<UDP<packet::DhcpPacket<EthernetAddr>>>>>(rec)?;

	return Ok(tmp.payload.payload.payload);
}

fn handle_request(mac: &pnet::datalink::MacAddr,
		tx: &mut std::boxed::Box<pnet::datalink::DataLinkSender>,
		allocator: &mut allocator::Allocator,
		request: packet::DhcpPacket<EthernetAddr>
		) {
	let client = lease::Client{hw_addr: request.client_hwaddr.clone(), client_identifier: None, hostname: None};
	let req_addr = request.options.iter().flat_map(|opt|
		match opt {
			&packet::DhcpOption::AddressRequest(ip) => Some(ip.clone()),
			_ => None
		}).next();

	if let Some(l) = allocator.get_allocation(&client, req_addr) {
		let addr = l.assigned.clone();
		let offer = packet::DhcpPacket {
			packet_type: packet::PacketType::Ack,
			xid: request.xid,
			seconds: 0,
			client_addr: None,
			your_addr: Some(addr.clone()),
			server_addr: Some(IPv4Addr([192, 168, 0, 1])),
			gateway_addr: None,
			client_hwaddr: request.client_hwaddr.clone(),
			options: vec![
				packet::DhcpOption::SubnetMask(IPv4Addr([255, 255, 255, 0])),
				packet::DhcpOption::LeaseTime(7200)
],
			flags: Vec::new(),
			};

		let udp = UDP { src: 67, dst: 68, payload: offer};
		let ip = IPv4Packet { src: IPv4Addr([192, 168, 0, 1]), dst:IPv4Addr([255, 255, 255, 255]), ttl: 64, protocol: 17, payload: udp};
		let ethernet = Ethernet{src: EthernetAddr([mac.0, mac.1, mac.2,
mac.3, mac.4, mac.5]), dst: request.client_hwaddr.clone(), eth_type: 0x0800, payload: ip};

		let tmp = serialize::serialize(&ethernet);
	
		tx.send_to(tmp.deref(), None);
	}
}

fn send_offer(mac: &pnet::datalink::MacAddr,
		tx: &mut std::boxed::Box<pnet::datalink::DataLinkSender>,
		allocator: &mut allocator::Allocator,
		discover: packet::DhcpPacket<EthernetAddr>
		) {
	let client = lease::Client{hw_addr: discover.client_hwaddr.clone(), client_identifier: None, hostname: None};
	if let Some(alloc) = allocator.allocation_for(&client) {
		let addr = alloc.assigned;
		let offer = packet::DhcpPacket {
			packet_type: packet::PacketType::Offer,
			xid: discover.xid,
			seconds: 0,
			client_addr: None,
			your_addr: Some(addr.clone()),
			server_addr: Some(IPv4Addr([192, 168, 0, 1])),
			gateway_addr: None,
			client_hwaddr: discover.client_hwaddr.clone(),
			options: vec![packet::DhcpOption::SubnetMask(IPv4Addr([255, 255, 255, 0]))],
			flags: Vec::new(),
			};
		
		let udp = UDP { src: 67, dst: 68, payload: offer};
		let ip = IPv4Packet { src: IPv4Addr([192, 168, 0, 1]), dst:IPv4Addr([255, 255, 255, 255]), ttl: 64, protocol: 17, payload: udp};
		let ethernet = Ethernet{src: EthernetAddr([mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]), dst: discover.client_hwaddr.clone(), eth_type: 0x0800, payload: ip};

		let tmp = serialize::serialize(&ethernet);
	
		tx.send_to(tmp.deref(), None);
	}
}

fn handle_packet(mac: &pnet::datalink::MacAddr,
		tx: &mut std::boxed::Box<pnet::datalink::DataLinkSender>,
		allocs: &mut allocator::Allocator,
		packet: packet::DhcpPacket<EthernetAddr>) {
	println!("Handling: {:?}", &packet);
	match &packet.packet_type {
		&packet::PacketType::Discover => send_offer(mac, tx, allocs, packet),
		&packet::PacketType::Request => handle_request(mac, tx, allocs, packet),
		_ => {},
	}
}

fn main() {
	let interfaces = datalink::interfaces();
	let interface = interfaces.into_iter().filter(|iface: &NetworkInterface | iface.name == "server").next().unwrap();
	let mac = interface.mac.unwrap();
	let pool = pool::IPPool::new((192 << 24) + (168 << 16) + 2, (192 << 24) + (168 << 16) + 15);
	let mut allocator = allocator::Allocator::new(pool);

	let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
		Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
		Ok(_) => panic!("Unhandles channel type!"),
		Err(e) => panic!("An error occured while creating ethernet channel: {}", e)
	};

	loop {
		let rec = rx.next().unwrap();
		let packet = decode_dhcp(&rec);
		println!("{:?}", &packet);
		match packet {
			Err(x) => println!("{:?}", x),
			Ok(x) => handle_packet(&mac, &mut tx, &mut allocator, x),
		}

		println!("{}", allocator.seralize_leases());
		println!("{}", allocator.seralize_allocs());
	}
}
