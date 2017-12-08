#[cfg(test)]
#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate rs_config_derive;
extern crate rs_config;

extern crate syslog;
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
    my_ip: Vec<Ipv4Addr>
}

impl Interface {
    fn save_to(&self, dir: &std::path::Path) {
        info!("Saving interface {}", &self.name);
        if !(dir.exists() && dir.is_dir()){
            warn!("Target directory for saving interface {} didn't exist", &self.name);
            return;
        }

        let my_dir = dir.join(&self.name);
        std::fs::create_dir_all(my_dir.as_path()).unwrap();

        for alloc in self.allocators.iter() {
            alloc.allocator.save_to(my_dir.as_path());
        }
    }
}

fn get_server_ip<'a, I>(arg: I, client: Ipv4Addr, mask: Ipv4Addr) -> Option<&'a Ipv4Addr>
    where I: IntoIterator<Item=&'a Ipv4Addr> {
    let cmp_mask: u32 = mask.into();
    let cmp_client: u32 = client.into();
    let cmp_v: u32 = cmp_mask & cmp_client;
    for ip in arg {
        let cmp_i: u32 = (*ip).into();
        let cmp: u32 = cmp_i & cmp_mask;
        if cmp_v ^ cmp == 0 {
            return Some(ip);
        }
    }

    return None;
}

fn alloc_for_client<'a>(aus: &'a mut Box<[AllocationUnit]>,
                        client: &lease::Client<::frame::ethernet::EthernetAddr>)
                        -> Option<&'a mut AllocationUnit> {
    aus.iter_mut().find(|alloc| alloc.selector.is_suitable(client))
}

impl AllocationUnit {

    //TODO: Pass debug info into here for logs?
    fn default_options(opts: &mut Vec<packet::DhcpOption>,
                       alloc: &allocator::Allocator) {
        if !opts.iter().any(|opt| opt.get_type() == 51) {
            info!("Defaulting lease time");
            opts.push(packet::DhcpOption::LeaseTime(86400));
        }

        if !opts.iter().any(|opt| opt.get_type() == 1) {
            warn!("Defaulting SubnetMask");

            let (min, max) = alloc.get_bounds();
            let min_u32: u32 = min.into();
            let max_u32: u32 = max.into();

            /* Get the number of bits in the netmask */
            let prefix = (min_u32 ^ max_u32).leading_zeros();
            let mask = (!0u32) << (32 - prefix);
            let val = Ipv4Addr::from(mask);

            opts.push(packet::DhcpOption::SubnetMask(val));
        }
    }

    fn new(conf: config::Pool, iface: &String) -> Self {
        let pool = conf.range.get_pool(iface);
        info!("Creating allocator for {} with pool {}", iface, pool.get_name());
        let mut allocator = allocator::Allocator::new(pool);
        let mut opts = conf.options;
        Self::default_options(&mut opts, &allocator);

        allocator.read_from(std::path::Path::new("/tmp/dhcpd").join(iface).as_path());

        return AllocationUnit {
            selector: conf.selector,
            options: opts.into_boxed_slice(),
            allocator: allocator
            };
    }
}

// This unwrap isn't really justified here, but it should really be in AllocationUnit, where the
// unwrap is justified by defaulting the mask into it on ::new()
fn get_mask<'a, I>(arg: I) -> &'a Ipv4Addr
    where I: IntoIterator<Item=&'a packet::DhcpOption> {
    match *arg.into_iter().find(|x| match **x {
            packet::DhcpOption::SubnetMask(_) => true,
            _ => false
        }).unwrap() {
        packet::DhcpOption::SubnetMask(ref mask) => mask,
        _ => panic!("Found non SubnetMask SubnetMask"),
    }
}


fn get_interface(conf: config::Interface)
        -> (Interface, Box<pnet::datalink::DataLinkSender>, Box<pnet::datalink::DataLinkReceiver>) {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().filter(|iface: &NetworkInterface | iface.name == conf.name.as_str()).next().unwrap();
    let mac = interface.mac.unwrap();

    debug!("Trying to open interface: {}", &conf.name);

    let (tx, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type!"),
        Err(e) => panic!("An error occured while creating ethernet channel: {}", e)
    };
    // I love/hate this silly borrow checker and the workarounds I come up with
    let name = conf.name;
    let pool = conf.pool;

    let allocs: Vec<AllocationUnit> = pool.into_iter().map(|x| AllocationUnit::new(x, &name)).collect();
    let ip = interface.ips.into_iter().flat_map(|x| match x {
            ipnetwork::IpNetwork::V4(net) => Some(net.ip()),
            _ => None,
        }).collect();

    let ret = Interface {
        name: name,
        my_mac: mac,
        my_ip: ip,
        allocators: allocs.into_boxed_slice()
        };
    info!("Using interface {} with local mac {} and ips {:?}", &ret.name, &ret.my_mac, &ret.my_ip);

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

    let ret = lease::Client {
        hw_addr: pack.client_hwaddr.clone(),
        hostname: hostname,
        client_identifier: ci
        };

    debug!("Created client: {:?}", &ret);

    return ret;
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
        let mask = *get_mask(au.options.iter());
        if let Some(l) = au.allocator.get_lease_for(&client, req_addr) {
            let addr = l.assigned.clone();
            let s_ip = match get_server_ip(&iface.my_ip, addr, mask) {
                    Some(i) => i,
                    None => {
                        error!("Tried to assign an IP I can't find a suitable server address for!");
                        return;
                    },
                };

            let mut opts = vec![
                packet::DhcpOption::ServerIdentifier(*s_ip)
                ];
            opts.extend(au.options.deref().iter().map(|x| (*x).clone()));
            let answer = packet::DhcpPacket {
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
            debug!("Replying to request: {:?}", &answer);

            let udp = UDP { src: 67, dst: 68, payload: answer};
            let ip = IPv4Packet { src: *s_ip, dst:Ipv4Addr::new(255, 255, 255, 255), ttl: 64, protocol: 17, payload: udp};
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
    if let Some(au) = alloc_for_client(&mut iface.allocators, &client) {
        if let Some(alloc) = au.allocator.get_allocation(&client, req_addr) {
            let mask = *get_mask(au.options.iter());
            let addr = alloc.assigned;
            let s_ip = match get_server_ip(&iface.my_ip, addr, mask) {
                    Some(i) => i,
                    None => {
                        error!("Tried to assign an IP I can't find a suitable server address for!");
                        return;
                    },
                };
            let offer = packet::DhcpPacket {
                packet_type: packet::PacketType::Offer,
                xid: discover.xid,
                seconds: 0,
                client_addr: None,
                your_addr: Some(addr.clone()),
                server_addr: None,
                gateway_addr: None,
                client_hwaddr: discover.client_hwaddr.clone(),
                options: vec![
                    packet::DhcpOption::ServerIdentifier(*s_ip)
                    ],
                flags: Vec::new(),
                };
            debug!("Making offer: {:?}", &offer);

            let udp = UDP { src: 67, dst: 68, payload: offer};
            let ip = IPv4Packet { src: *s_ip, dst:Ipv4Addr::new(255, 255, 255, 255), ttl: 64, protocol: 17, payload: udp};
            let mac = &iface.my_mac;
            let ethernet = Ethernet{src: EthernetAddr::from(mac), dst: discover.client_hwaddr.clone(), eth_type: 0x0800, payload: ip};

            let tmp = serialize::serialize(&ethernet);

            tx.send_to(tmp.deref(), None);
        }
    }
}

fn handle_packet(
        tx: &mut std::boxed::Box<pnet::datalink::DataLinkSender>,
        iface: &mut Interface,
        packet: packet::DhcpPacket<EthernetAddr>) {
    match packet.packet_type {
        packet::PacketType::Discover => {
            trace!("Creating an offer");
            send_offer(tx, iface, packet)
        },
        packet::PacketType::Request => {
            trace!("Handling a request");
            handle_request(tx, iface, packet)
        },
        x => {
            warn!("Found unhandled dhcp packet type: {:?}", x);
        },
    }
}

fn main() {
    syslog::init(syslog::Facility::LOG_DAEMON, log::LogLevel::Trace.to_log_level_filter(), Some("dhcpd")).unwrap();
    trace!("Starting up dhcp server");
    let conf: config::Interface = rs_config::read_or_exit("/etc/dhcp/dhcpd.conf");

    let (mut iface, mut tx, mut rx)  = get_interface(conf);

    loop {
        trace!("Going into receive loop");
        let rec = rx.next().unwrap();
        trace!("Received something");
        let packet = decode_dhcp(&rec);
        debug!("{:?}", &packet);
        match packet {
            Err(_) => {},
            Ok(x) => handle_packet(&mut tx, &mut iface, x),
        }

        iface.save_to(std::path::Path::new("/tmp/dhcpd"));
    }
}
