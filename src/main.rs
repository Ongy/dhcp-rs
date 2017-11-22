extern crate pnet;

mod packet;
mod frame;
mod pool;
mod serialize;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel;

use std::ops::Deref;

use frame::ethernet::{Ethernet, EthernetAddr};
use frame::ip4::{IPv4Packet, IPv4Addr};
use frame::udp::UDP;

fn decode_dhcp(rec: &[u8]) -> Result<packet::DhcpPacket<EthernetAddr>, String> {
	let tmp =
serialize::deserialize::<Ethernet<IPv4Packet<UDP<packet::DhcpPacket<EthernetAddr>>>>>(rec)?;

	return Ok(tmp.payload.payload.payload);
}

fn send_offer(mac: &pnet::datalink::MacAddr,
		tx: &mut std::boxed::Box<pnet::datalink::DataLinkSender>,
		pool: &mut pool::IPPool,
		discover: packet::DhcpPacket<EthernetAddr>
		) {
	if let Some(ip) = pool.next() {
		let offer = packet::DhcpPacket {
			packet_type: packet::PacketType::Offer,
			xid: discover.xid,
			seconds: 0,
			client_addr: Some(IPv4Addr([(ip >> 24) as u8, (ip >> 16) as u8, (ip >> 8) as u8, ip as u8])),
			your_addr: Some(IPv4Addr([192, 168, 0, 1])),
			server_addr: None,
			gateway_addr: None,
			client_hwaddr: discover.client_hwaddr.clone(),
			options: vec![packet::DhcpOption::SubnetMask(IPv4Addr([255, 255, 255, 0]))],
			flags: Vec::new(),
			};
		
		let udp = UDP { src: 67, dst: 68, payload: offer};
		let ip = IPv4Packet { src: IPv4Addr([192, 168, 0, 1]), dst:IPv4Addr([255, 255, 255, 255]), ttl: 64, protocol: 17, payload: udp};
		let ethernet = Ethernet{src: EthernetAddr([mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]), dst: EthernetAddr(discover.client_hwaddr.0), eth_type: 0x0800, payload: ip};

		let tmp = serialize::serialize(&ethernet);
	
		tx.send_to(tmp.deref(), None);
	}
}

fn main() {
	let interfaces = datalink::interfaces();
	let interface = interfaces.into_iter().filter(|iface: &NetworkInterface | iface.name == "server").next().unwrap();
	let mac = interface.mac.unwrap();
	let mut pool = pool::IPPool::new((192 << 24) + (168 << 16) + 2, (192 << 24) + (168 << 16) + 15);

	let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
		Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
		Ok(_) => panic!("Unhandles channel type!"),
		Err(e) => panic!("An error occured while creating ethernet channel: {}", e)
	};

	loop {
		let rec = rx.next().unwrap();
		let packet = decode_dhcp(&rec);
		match packet {
			Err(x) => println!("{:?}", x),
			Ok(x) => send_offer(&mac, &mut tx, &mut pool, x),
		}
	}
}
