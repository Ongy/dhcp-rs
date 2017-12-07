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
extern crate ipnetwork;

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
use frame::ip4::{IPv4Packet};
use frame::udp::UDP;
use std::net::Ipv4Addr;

struct AllocationUnit {
    selector: config::Selector,
    allocator: allocator::Allocator,
    options: Box<[packet::DhcpOption]>,
}

struct Interface {
    allocators: Box<[AllocationUnit]>,
    name: String,
    my_mac: pnet::datalink::MacAddr,
    _my_ip: Vec<Ipv4Addr>
}

impl Interface {
    fn save_to(&self, dir: &std::path::Path) {
        if !(dir.exists() && dir.is_dir()){
            return;
        }

        let my_dir = dir.join(&self.name);
        std::fs::create_dir_all(my_dir.as_path()).unwrap();

        for alloc in self.allocators.iter() {
            alloc.allocator.save_to(my_dir.as_path());
        }
    }
}

fn alloc_for_client<'a>(aus: &'a mut Box<[AllocationUnit]>, client: &lease::Client<::frame::ethernet::EthernetAddr>) -> Option<&'a mut AllocationUnit> {
    aus.iter_mut().find(|alloc| alloc.selector.is_suitable(client))
}

fn get_allocation(conf: config::Pool, iface: &String) -> AllocationUnit {
    let pool = conf.range.get_pool(iface);
    let mut allocator = allocator::Allocator::new(pool);

    allocator.read_from(std::path::Path::new("/tmp/dhcpd"));

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

    let (tx, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type!"),
        Err(e) => panic!("An error occured while creating ethernet channel: {}", e)
    };
    // I love/hate this silly borrow checker and the workarounds I come up with
    let name = conf.name;
    let pool = conf.pool;

    let allocs: Vec<AllocationUnit> = pool.into_iter().map(|x| get_allocation(x, &name)).collect();
    let ip = interface.ips.into_iter().flat_map(|x| match x {
            ipnetwork::IpNetwork::V4(net) => Some(net.ip()),
            _ => None,
        }).collect();

    let ret = Interface {
        name: name,
        my_mac: mac,
        _my_ip: ip,
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

fn handle_request(
        tx: &mut std::boxed::Box<pnet::datalink::DataLinkSender>,
        iface: &mut Interface,
        request: packet::DhcpPacket<EthernetAddr>
        ) {
    let client = get_client(&request);
    let req_addr = request.options.iter().flat_map(|opt|
        match opt {
            &packet::DhcpOption::AddressRequest(ip) => Some(ip.clone()),
            _ => None
        }).next();
    if let Some(au) = alloc_for_client(&mut iface.allocators, &client) {

        if let Some(l) = au.allocator.get_lease_for(&client, req_addr) {
            let mut opts = vec![
                packet::DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                packet::DhcpOption::LeaseTime(l.lease_duration),
                packet::DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 0, 1))
                ];
            opts.extend(au.options.deref().iter().map(|x| (*x).clone()));
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
            let ip = IPv4Packet { src: Ipv4Addr::new(192, 168, 0, 1), dst:Ipv4Addr::new(255, 255, 255, 255), ttl: 64, protocol: 17, payload: udp};
            let mac = &iface.my_mac;
            let ethernet = Ethernet{src: EthernetAddr::from(mac), dst: request.client_hwaddr.clone(), eth_type: 0x0800, payload: ip};

            let tmp = serialize::serialize(&ethernet);

            tx.send_to(tmp.deref(), None);
        }
    }
}

fn send_offer(
        tx: &mut std::boxed::Box<pnet::datalink::DataLinkSender>,
        iface: &mut Interface,
        discover: packet::DhcpPacket<EthernetAddr>
        ) {
    let client = get_client(&discover);
    let req_addr = discover.options.iter().flat_map(|opt|
        match *opt {
            packet::DhcpOption::AddressRequest(ip) => Some(ip.clone()),
            _ => None
        }).next();
    let a = alloc_for_client(&mut iface.allocators, &client);
    if let Some(alloc) = a.and_then(|au| au.allocator.get_allocation(&client, req_addr)) {
        let addr = alloc.assigned;
        let offer = packet::DhcpPacket {
            packet_type: packet::PacketType::Offer,
            xid: discover.xid,
            seconds: 0,
            client_addr: None,
            your_addr: Some(addr.clone()),
            server_addr: Some(Ipv4Addr::new(192, 168, 0, 1)),
            gateway_addr: None,
            client_hwaddr: discover.client_hwaddr.clone(),
            options: vec![
                packet::DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                packet::DhcpOption::LeaseTime(7200),
                packet::DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 0, 1))
                ],
            flags: Vec::new(),
            };

        let udp = UDP { src: 67, dst: 68, payload: offer};
        let ip = IPv4Packet { src: Ipv4Addr::new(192, 168, 0, 1), dst:Ipv4Addr::new(255, 255, 255, 255), ttl: 64, protocol: 17, payload: udp};
        let mac = &iface.my_mac;
        let ethernet = Ethernet{src: EthernetAddr::from(mac), dst: discover.client_hwaddr.clone(), eth_type: 0x0800, payload: ip};

        let tmp = serialize::serialize(&ethernet);

        tx.send_to(tmp.deref(), None);
    }
}

fn handle_packet(
        tx: &mut std::boxed::Box<pnet::datalink::DataLinkSender>,
        iface: &mut Interface,
        packet: packet::DhcpPacket<EthernetAddr>) {
    println!("Handling: {:?}", &packet);
    match &packet.packet_type {
        &packet::PacketType::Discover => send_offer(tx, iface, packet),
        &packet::PacketType::Request => handle_request(tx, iface, packet),
        _ => {},
    }
}

fn main() {
    let conf: config::Interface = rs_config::read_or_exit("/etc/dhcp/dhcpd.conf");

    let (mut iface, mut tx, mut rx)  = get_interface(conf);

    loop {
        let rec = rx.next().unwrap();
        let packet = decode_dhcp(&rec);
        println!("{:?}", &packet);
        match packet {
            Err(x) => println!("{:?}", x),
            Ok(x) => handle_packet(&mut tx, &mut iface, x),
        }

        iface.save_to(std::path::Path::new("/tmp/dhcpd"));
    }
}
