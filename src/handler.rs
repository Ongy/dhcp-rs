use std;
use pnet;
use serialize;
use config;

use std::marker::PhantomData;
use interface::Interface;
use std::ops::Deref;

use frame::ethernet::{Ethernet, EthernetAddr};
use frame::ip4::{IPv4Packet};
use frame::udp::UDP;
use std::net::Ipv4Addr;

use packet;
use lease;
use allocationunit;

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

    None
}

fn alloc_for_client<'a>(aus: &'a mut [allocationunit::AllocationUnit],
                        client: &lease::Client<::frame::ethernet::EthernetAddr>)
                        -> Option<&'a mut allocationunit::AllocationUnit> {
    aus.iter_mut().find(|alloc| alloc.is_suitable(client))
}

fn decode_dhcp(rec: &[u8]) -> Result<packet::DhcpPacket<EthernetAddr>, String> {
    let tmp = serialize::deserialize::<Ethernet<IPv4Packet<UDP<packet::DhcpPacket<EthernetAddr>, packet::DhcpServer>>>>(rec)?;
    Ok(tmp.payload.payload.payload)
}

#[allow(unknown_lints,needless_pass_by_value)]
fn get_ack(iface: &mut Interface, request: packet::DhcpPacket<EthernetAddr>) -> Option<(packet::DhcpPacket<EthernetAddr>, Ipv4Addr)> {
    let client = lease::get_client(&request);
    let req_addr = request.options.iter().filter_map(|opt|
        match *opt {
            packet::DhcpOption::AddressRequest(ip) => Some(ip),
            _ => None
        }).next();
    if let Some(au) = alloc_for_client(&mut iface.allocators, &client) {
        let mask = *au.get_mask();
        let mut opts: Vec<packet::DhcpOption> = au.get_options().iter().map(|x| (*x).clone()).collect();
        if let Some(l) = au.get_renewed_lease(&client, req_addr) {
            let addr = l.assigned;
            let s_ip = match get_server_ip(&iface.my_ip, addr, mask) {
                    Some(i) => i,
                    None => {
                        error!("Tried to assign an IP I can't find a suitable server address for!");
                        return None;
                    },
                };

            opts.push(packet::DhcpOption::ServerIdentifier(*s_ip));
            let answer = packet::DhcpPacket {
                packet_type: packet::PacketType::Ack,
                xid: request.xid,
                seconds: 0,
                client_addr: None,
                your_addr: Some(addr),
                server_addr: None,
                gateway_addr: None,
                client_hwaddr: request.client_hwaddr,
                options: opts,
                flags: Vec::new(),
                };
            debug!("Replying to request: {:?}", &answer);
            return Some((answer, *s_ip));
        }

        let answer = packet::DhcpPacket {
            packet_type: packet::PacketType::Nack,
            xid: request.xid,
            seconds: 0,
            client_addr: None,
            your_addr: None,
            server_addr: None,
            gateway_addr: None,
            client_hwaddr: request.client_hwaddr,
            options: vec![packet::DhcpOption::Message("Can't give you this address. Did I offer it?".into())],
            flags: Vec::new(),
            };
        let s_ip = iface.my_ip[0];

        return Some((answer, s_ip))
    }
    let answer = packet::DhcpPacket {
        packet_type: packet::PacketType::Nack,
        xid: request.xid,
        seconds: 0,
        client_addr: None,
        your_addr: None,
        server_addr: None,
        gateway_addr: None,
        client_hwaddr: request.client_hwaddr,
        options: vec![packet::DhcpOption::Message("Can't find a viable allocator for this client".into())],
        flags: Vec::new(),
        };
    let s_ip = iface.my_ip[0];

    Some((answer, s_ip))
}

// TODO: This is horrible
fn get_offer_alloc<'a>(au: &'a mut allocationunit::AllocationUnit,
                       client: &lease::Client<::frame::ethernet::EthernetAddr>,
                       req: Option<Ipv4Addr>)
                       -> Option<&'a lease::Allocation<EthernetAddr, Ipv4Addr>> {
    let _ = au.get_allocation(client, req);
    au.get_allocation(client, None)
}

#[allow(unknown_lints,needless_pass_by_value)]
fn get_offer(iface: &mut Interface, discover: packet::DhcpPacket<EthernetAddr>) -> Option<(packet::DhcpPacket<EthernetAddr>, Ipv4Addr)> {
    let client = lease::get_client(&discover);
    let req_addr = discover.options.iter().flat_map(|opt|
        match *opt {
            packet::DhcpOption::AddressRequest(ip) => Some(ip),
            _ => None
        }).next();
    if let Some(mut au) = alloc_for_client(&mut iface.allocators, &client) {
        let mask = *au.get_mask();
        let mut opts: Vec<packet::DhcpOption> = au.get_options().iter().map(|x| (*x).clone()).collect();
        if let Some(alloc) = get_offer_alloc(&mut au, &client, req_addr) {
            let addr = alloc.assigned;
            let s_ip = match get_server_ip(&iface.my_ip, addr, mask) {
                    Some(i) => i,
                    None => {
                        error!("Tried to assign an IP I can't find a suitable server address for!");
                        return None;
                    },
                };
            opts.push(packet::DhcpOption::ServerIdentifier(*s_ip));
            let offer = packet::DhcpPacket {
                packet_type: packet::PacketType::Offer,
                xid: discover.xid,
                seconds: 0,
                client_addr: None,
                your_addr: Some(addr),
                server_addr: None,
                gateway_addr: None,
                client_hwaddr: discover.client_hwaddr,
                options: opts,
                flags: Vec::new(),
                };
            debug!("Making offer: {:?}", &offer);
            return Some((offer, *s_ip));
        }
    }

    None
}

//TODO: Check what exactly we need in here
#[allow(unknown_lints,needless_pass_by_value)]
fn get_inform(iface: &mut Interface, discover: packet::DhcpPacket<EthernetAddr>) -> Option<(packet::DhcpPacket<EthernetAddr>, Ipv4Addr)> {
    let client = lease::get_client(&discover);
    if let Some(au) = alloc_for_client(&mut iface.allocators, &client) {
        let opts: Vec<packet::DhcpOption> = au.get_options().iter().map(|x| (*x).clone()).collect();
        let offer = packet::DhcpPacket {
            packet_type: packet::PacketType::Offer,
            xid: discover.xid,
            seconds: 0,
            client_addr: None,
            your_addr: None,
            server_addr: None,
            gateway_addr: None,
            client_hwaddr: discover.client_hwaddr,
            options: opts,
            flags: Vec::new(),
            };
        debug!("Informing: {:?}", &offer);
        let s_ip = iface.my_ip[0];
        return Some((offer, s_ip));
    }

    None
}

fn get_answer(iface: &mut Interface, packet: packet::DhcpPacket<EthernetAddr>) -> Option<(packet::DhcpPacket<EthernetAddr>, Ipv4Addr)> {
    match packet.packet_type {
        packet::PacketType::Discover => {
            trace!("Creating an offer");
            get_offer(iface, packet)
        },
        packet::PacketType::Request => {
            trace!("Handling a request");
            get_ack(iface, packet)
        },
        packet::PacketType::Inform => {
            trace!("Someone wants to get informed");
            get_inform(iface, packet)
        }
        x => {
            warn!("Found unhandled dhcp packet type: {:?}", x);
            None
        },
    }
}

fn handle_packet(
        tx: &mut std::boxed::Box<pnet::datalink::DataLinkSender>,
        iface: &mut Interface,
        packet: packet::DhcpPacket<EthernetAddr>) {
    let target_mac = packet.client_hwaddr;
    if let Some((answer, s_ip)) = get_answer(iface, packet) {

        let udp: UDP<packet::DhcpPacket<EthernetAddr>, packet::DhcpServer>  = UDP {remote: 68, payload: answer, local: PhantomData};
        let ip = IPv4Packet { src: s_ip, dst:Ipv4Addr::new(255, 255, 255, 255), ttl: 64, payload: udp};
        let ethernet = Ethernet{src: EthernetAddr::from(&iface.my_mac), dst: target_mac, payload: ip};

        let tmp = serialize::serialize(&ethernet);

        tx.send_to(tmp.deref(), None);
    }
}

pub fn handle_interface(conf: config::Interface,
                        cache: String)
                        -> std::thread::JoinHandle<()> {

    let (mut iface, mut tx, mut rx)  = Interface::get(conf, &cache);

    std::thread::spawn(move || {
        loop {
            trace!("Going into receive loop");
            match rx.next() {
                Ok(rec) => {
                    trace!("Received something");
                    let packet = decode_dhcp(rec);
                    debug!("{:?}", &packet);
                    match packet {
                        Err(_) => {},
                        Ok(x) => {
                            handle_packet(&mut tx, &mut iface, x);
                            iface.save_to(&cache);
                        },
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        trace!("Ethernet read syscall got interrupted");
                        continue;
                    }
                    error!("Failed to read from ethernet socket: {}", e);
                    break;
                }
            }
        }
    })
}
