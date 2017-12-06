#[cfg(test)]
#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate rs_config_derive;
extern crate rs_config;

extern crate pnet;
extern crate time;

mod frame;
mod lease;
mod packet;
mod pool;
mod serialize;
mod allocator;
mod config;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel;

use std::ops::Deref;

use frame::ethernet::{Ethernet, EthernetAddr};
use frame::ip4::{IPv4Packet, IPv4Addr};
use frame::udp::UDP;

struct AllocationUnit {
    selector: config::Selector,
    allocator: allocator::Allocator,
    options: Box<[packet::DhcpOption]>,
}

struct Interface {
    allocators: Box<[AllocationUnit]>,
    name: String,
    my_mac: pnet::datalink::MacAddr,
    my_ip: Vec<IPv4Addr>
}

fn get_allocation(conf: config::Pool, iface: &String) -> AllocationUnit {
    let pool = conf.range.get_pool(iface);
    let mut allocator = allocator::Allocator::new(pool);

    return AllocationUnit {
        selector: conf.selector,
        options: conf.options.into_boxed_slice(),
        allocator: allocator
        };
}

fn get_interface(conf: config::Interface)
        -> (Interface, Box<pnet::datalink::DataLinkSender>, Box<pnet::datalink::DataLinkReceiver>) {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().filter(|iface: &NetworkInterface | iface.name == conf.name.as_str()).next().unwrap();
    let mac = interface.mac.unwrap();
    let ip = interface.ips.into_iter().next().unwrap();
    let allocs: Vec<AllocationUnit> = conf.pool.into_iter().map(|x| get_allocation(x, &conf.name)).collect();

    let (tx, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type!"),
        Err(e) => panic!("An error occured while creating ethernet channel: {}", e)
    };

    let ret = Interface {
        name: conf.name,
        my_mac: mac,
        my_ip: ip,
        allocators: allocs.into_boxed_slice()
        };

    return (ret, tx, rx);
}

fn decode_dhcp(rec: &[u8]) -> Result<packet::DhcpPacket<EthernetAddr>, String> {
    let tmp = serialize::deserialize::<Ethernet<IPv4Packet<UDP<packet::DhcpPacket<EthernetAddr>>>>>(rec)?;
    return Ok(tmp.payload.payload.payload);
}

fn get_client(pack: &packet::DhcpPacket<EthernetAddr>) -> lease::Client<EthernetAddr> {
    let hostname = pack.options.iter().filter_map(|opt|
        match opt {
            &packet::DhcpOption::Hostname(ref name) => Some(name.clone()),
            _ => None
        }).next();
    let ci = pack.options.iter().filter_map(|opt|
        match opt {
            &packet::DhcpOption::ClientIdentifier(ref c) => Some(c.clone()),
            _ => None
        }).next();

    return lease::Client {
        hw_addr: pack.client_hwaddr.clone(),
        hostname: hostname,
        client_identifier: ci
        };
}

fn handle_request(mac: &pnet::datalink::MacAddr,
        tx: &mut std::boxed::Box<pnet::datalink::DataLinkSender>,
        allocator: &mut allocator::Allocator,
        options: &Box<[packet::DhcpOption]>,
        request: packet::DhcpPacket<EthernetAddr>
        ) {
    let client = get_client(&request);
    let req_addr = request.options.iter().flat_map(|opt|
        match opt {
            &packet::DhcpOption::AddressRequest(ip) => Some(ip.clone()),
            _ => None
        }).next();


    if let Some(l) = allocator.get_lease_for(&client, req_addr) {
        let mut opts = vec![
            packet::DhcpOption::SubnetMask(IPv4Addr([255, 255, 255, 0])),
            packet::DhcpOption::LeaseTime(l.lease_duration),
            packet::DhcpOption::ServerIdentifier(IPv4Addr([192, 168, 0, 1]))
            ];
        opts.extend(options.deref().iter().map(|x| (*x).clone()));
        let addr = l.assigned.clone();
        let offer = packet::DhcpPacket {
            packet_type: packet::PacketType::Ack,
            xid: request.xid,
            seconds: 0,
            client_addr: None,
            your_addr: Some(addr.clone()),
            server_addr: None,
            gateway_addr: None,
            client_hwaddr: request.client_hwaddr.clone(),
            options: opts,
            flags: Vec::new(),
            };

        let udp = UDP { src: 67, dst: 68, payload: offer};
        let ip = IPv4Packet { src: IPv4Addr([192, 168, 0, 1]), dst:IPv4Addr([255, 255, 255, 255]), ttl: 64, protocol: 17, payload: udp};
        let ethernet = Ethernet{src: EthernetAddr([mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]), dst: request.client_hwaddr.clone(), eth_type: 0x0800, payload: ip};

        let tmp = serialize::serialize(&ethernet);

        tx.send_to(tmp.deref(), None);
    }
}

fn send_offer(mac: &pnet::datalink::MacAddr,
        tx: &mut std::boxed::Box<pnet::datalink::DataLinkSender>,
        allocator: &mut allocator::Allocator,
        discover: packet::DhcpPacket<EthernetAddr>
        ) {
    let client = get_client(&discover);
    let req_addr = discover.options.iter().flat_map(|opt|
        match opt {
            &packet::DhcpOption::AddressRequest(ip) => Some(ip.clone()),
            _ => None
        }).next();
    if let Some(alloc) = allocator.get_allocation(&client, req_addr) {
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
            options: vec![
                packet::DhcpOption::SubnetMask(IPv4Addr([255, 255, 255, 0])),
                packet::DhcpOption::LeaseTime(7200),
                packet::DhcpOption::ServerIdentifier(IPv4Addr([192, 168, 0, 1]))
                ],
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
        options: &Box<[packet::DhcpOption]>,
        packet: packet::DhcpPacket<EthernetAddr>) {
    println!("Handling: {:?}", &packet);
    match &packet.packet_type {
        &packet::PacketType::Discover => send_offer(mac, tx, allocs, packet),
        &packet::PacketType::Request => handle_request(mac, tx, allocs, options, packet),
        _ => {},
    }
}

fn main() {
    let _conf: config::Interface = rs_config::read_or_exit("/etc/dhcp/dhcpd.conf");

    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().filter(|iface: &NetworkInterface | iface.name == "server").next().unwrap();
    let mac = interface.mac.unwrap();
    let pool = pool::IPPool::new(IPv4Addr([192, 168, 0, 0]), IPv4Addr([192, 168, 0, 15]));
    let options = vec![
        packet::DhcpOption::DomainNameServer(vec![
             IPv4Addr([10, 0, 0, 1]),
             IPv4Addr([10, 149, 107, 130])
            ].into_boxed_slice())
        ].into_boxed_slice();
    let mut allocator = allocator::Allocator::new(pool);

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type!"),
        Err(e) => panic!("An error occured while creating ethernet channel: {}", e)
    };

    loop {
        let rec = rx.next().unwrap();
        let packet = decode_dhcp(&rec);
        println!("{:?}", &packet);
        match packet {
            Err(x) => println!("{:?}", x),
            Ok(x) => handle_packet(&mac, &mut tx, &mut allocator, &options, x),
        }

        println!("{}", allocator.seralize_leases());
        println!("{}", allocator.seralize_allocs());
    }
}
