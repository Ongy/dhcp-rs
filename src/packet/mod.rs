extern crate rs_config;
extern crate byteorder;

mod name;
use self::name::DomainNames;

use rs_config::ConfigAble;

use self::byteorder::{WriteBytesExt, NetworkEndian, ByteOrder};

use std::boxed::Box;
use std::iter;
use std::option::Option;
use std::result::Result;
use std::vec::Vec;
use std::collections::HashMap;

use serialize::{Serializeable, HasCode};

#[cfg(test)]
use quickcheck::Arbitrary;
#[cfg(test)]
use quickcheck::Gen;

use frame::ethernet::EthernetAddr;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct DhcpServer;

impl HasCode for DhcpServer {
    type CodeType = u16;
    fn get_code() -> Self::CodeType { 67 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ConfigAble)]
pub enum PacketType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nack,
    Release,
    Inform
}

#[cfg(test)]
impl Arbitrary for PacketType {
    fn arbitrary<G: Gen>(gen: &mut G) -> Self {
        Self::from_value(u8::arbitrary(gen) % 8 + 1).unwrap()
    }
}

impl PacketType {
    fn push_value(&self, buffer: &mut Vec<u8>) {
        #![allow(unknown_lints,match_same_arms)]
        let val = match *self {
            PacketType::Discover => 0x1,
            PacketType::Offer => 0x2,
            PacketType::Request => 0x3,
            PacketType::Decline => 0x4,
            PacketType::Ack => 0x5,
            PacketType::Nack => 0x6,
            PacketType::Release => 0x7,
            PacketType::Inform => 0x8,
        };
        buffer.push(val);
    }

    fn push_to(&self, buffer: &mut Vec<u8>) {
        buffer.push(53);
        buffer.push(0x1);
        self.push_value(buffer);
    }

    fn from_value(val: u8) -> Result<Self, String> {
        match val {
            0x1 => Ok(PacketType::Discover),
            0x2 => Ok(PacketType::Offer),
            0x3 => Ok(PacketType::Request),
            0x4 => Ok(PacketType::Decline),
            0x5 => Ok(PacketType::Ack),
            0x6 => Ok(PacketType::Nack),
            0x7 => Ok(PacketType::Release),
            0x8 => Ok(PacketType::Inform),
            x => Err(format!("Encountered unexpected value for dhcp packet type: {}", x))
        }
    }

    #[cfg(test)]
    fn from_buffer(buffer: &[u8]) -> Result<Self, String> {
        if buffer[0] != 53 {
            return Err(format!("Encountered unexpected option type for dhcp packet type: {}", buffer[0]));
        }

        if buffer[1] != 0x1 {
            return Err(format!("Encountered unexpected option length for dhcp packet type: {}", buffer[1]));
        }

        Self::from_value(buffer[2])
    }

    fn get_op(&self) -> u8 {
        match *self {
        #![allow(unknown_lints,match_same_arms)]
            PacketType::Discover => 0x1,
            PacketType::Offer => 0x2,
            PacketType::Request | PacketType::Decline => 0x1,
            PacketType::Ack | PacketType::Nack => 0x2,
            PacketType::Release | PacketType::Inform => 0x1,
        }
    }
}

pub trait HwAddr {
    fn size() -> u8;
    fn hwtype() -> u8;
    fn push_to(&self, &mut Vec<u8>);
    fn from_buffer(& [u8]) -> Self;
}

impl HwAddr for EthernetAddr {
    fn size() -> u8 { 6 }

    fn hwtype() -> u8 { 0x1 }

    fn push_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.0.iter());
    }

    fn from_buffer(buffer: & [u8]) -> Self {
        let mut array = [0; 6];
        array.copy_from_slice(&buffer[..6]);
        EthernetAddr(array)
    }
}

//TODO: Pretty this up
impl HwAddr for Ipv4Addr {
    fn size() -> u8 {4}
    fn hwtype() -> u8{0}
    fn push_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.octets().iter());
    }

    fn from_buffer(buffer: &[u8]) -> Self {
        let mut array = [0; 4];
        array.copy_from_slice(&buffer[..4]);
        Ipv4Addr::from(array)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ConfigAble)]
pub struct ClasslessRoute {
    pub net: Ipv4Addr,
    pub prefix: u8,
    pub router: Ipv4Addr
}

impl ClasslessRoute {
    fn get_size(&self) -> u8 {
        let octets = Self::get_octets(self.prefix) as u8;
        1 + octets + 4
    }

    fn push_to(&self, buffer: &mut Vec<u8>) {
        let octets = Self::get_octets(self.prefix);
        buffer.push(self.prefix);
        buffer.extend(self.net.octets().iter().take(octets as usize));
        self.router.push_to(buffer);
    }

    fn from_buffer(buffer: &[u8]) -> Result<Self, String> {
        if buffer.len() < 1 {
            return Err(String::from("Got empty buffer for classless routes"));
        }
        let len = buffer[0];

        if len > 32 {
            return Err(String::from("Got invalid length value for classless route"));
        }
        let octets = Self::get_octets(len);
        if buffer.len() < 1 + octets + 4 {
            return Err(String::from("Classless route Network + router would be longer than the buffer"));
        }

        let mut array = [0; 4];
        array[0..octets].copy_from_slice(&buffer[1..1 + octets]);
        let net = Ipv4Addr::from(array);
        let router = Ipv4Addr::from_buffer(&buffer[1 + octets..]);

        Ok(ClasslessRoute {net: net, prefix: len, router: router})
    }

    fn get_octets(bits: u8) -> usize {
        let len = bits / 8;
        if bits % 8 != 0 {
            return len as usize + 1;
        }

        len as usize
    }
}

#[cfg(test)]
impl Arbitrary for ClasslessRoute {
    fn arbitrary<G: Gen>(gen: &mut G) -> Self {
        let mut net: [u8;4] = [Arbitrary::arbitrary(gen), Arbitrary::arbitrary(gen), Arbitrary::arbitrary(gen), Arbitrary::arbitrary(gen)];
        let prefix = u8::arbitrary(gen) % 32;
        let router = Arbitrary::arbitrary(gen);

        let octets = Self::get_octets(prefix);

        for i in octets..4 {
            net[i as usize] = 0;
        }

        ClasslessRoute {
            net: Ipv4Addr::from(net),
            prefix: prefix,
            router: router
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ConfigAble)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr), //This should probably be a better type
    Router(Box<[Ipv4Addr]>),
    DomainNameServer(Box<[Ipv4Addr]>),
    Hostname(String),
    DomainName(String),
    BroadcastAddress(Ipv4Addr),
    LeaseTime(u32),
    AddressRequest(Ipv4Addr),
    MessageType(PacketType),
    ServerIdentifier(Ipv4Addr),
    Message(String),
    RenewalTime(u32),
    RebindingTime(u32),
    ClientIdentifier(Box<[u8]>),
    DomainSearch(DomainNames),
    ClasslessRoutes(Box<[ClasslessRoute]>),
    Unknown(u8, Box<[u8]>),
}

#[cfg(test)]
impl Arbitrary for DhcpOption {
    fn arbitrary<G: Gen>(gen: &mut G) -> Self {
        match u8::arbitrary(gen) % 16 {
            0  => DhcpOption::SubnetMask(Arbitrary::arbitrary(gen)),
            1  => {
                let vec: Vec<Ipv4Addr> = Arbitrary::arbitrary(gen);
                let vec2: Vec<Ipv4Addr> = vec.into_iter().take(32).collect();
                DhcpOption::Router(vec2.into_boxed_slice())
            },
            2  => {
                let vec: Vec<Ipv4Addr> = Arbitrary::arbitrary(gen);
                let vec2: Vec<Ipv4Addr> = vec.into_iter().take(32).collect();
                DhcpOption::DomainNameServer(vec2.into_boxed_slice())
            },
            3  => DhcpOption::Hostname(Arbitrary::arbitrary(gen)),
            4  => DhcpOption::DomainName(Arbitrary::arbitrary(gen)),
            5  => DhcpOption::BroadcastAddress(Arbitrary::arbitrary(gen)),
            6  => DhcpOption::LeaseTime(Arbitrary::arbitrary(gen)),
            7  => DhcpOption::AddressRequest(Arbitrary::arbitrary(gen)),
            8  => DhcpOption::MessageType(Arbitrary::arbitrary(gen)),
            9  => DhcpOption::ServerIdentifier(Arbitrary::arbitrary(gen)),
            10 => DhcpOption::Message(Arbitrary::arbitrary(gen)),
            11 => DhcpOption::RenewalTime(Arbitrary::arbitrary(gen)),
            12 => DhcpOption::RebindingTime(Arbitrary::arbitrary(gen)),
            13 => {
                let vec: Vec<u8> = Arbitrary::arbitrary(gen);
                let vec2: Vec<u8> = vec.into_iter().take(255).collect();
                DhcpOption::ClientIdentifier(vec2.into_boxed_slice())
            },
            //TODO: Reenable when the long option parsing is in
            //13 => DhcpOption::DomainSearch(/*Arbitrary::arbitrary(gen)*/vec![]),
            14 => {
                let vec: Vec<ClasslessRoute> = Arbitrary::arbitrary(gen);
                let vec2: Vec<ClasslessRoute> = vec.into_iter().take(28).collect();
                DhcpOption::ClasslessRoutes(vec2.into_boxed_slice())
            },
            15 => {
                let vec: Vec<u8> = Arbitrary::arbitrary(gen);
                let vec2: Vec<u8> = vec.into_iter().take(255).collect();
                DhcpOption::Unknown(13 as u8, vec2.into_boxed_slice())
            },
            _ => panic!("Hit impossible case!"),
        }
    }
}

impl DhcpOption {
    pub fn get_type(&self) -> u8 {
        match *self {
            DhcpOption::SubnetMask(_) => 1,
            DhcpOption::Router(_) => 3,
            DhcpOption::DomainNameServer(_) => 6,
            DhcpOption::Hostname(_) => 12,
            DhcpOption::DomainName(_) => 15,
            DhcpOption::BroadcastAddress(_) => 28,
            DhcpOption::AddressRequest(_) => 50,
            DhcpOption::LeaseTime(_) => 51,
            DhcpOption::MessageType(_) => 53,
            DhcpOption::ServerIdentifier(_) => 54,
            DhcpOption::Message(_) => 56,
            DhcpOption::RenewalTime(_) => 58,
            DhcpOption::RebindingTime(_) => 59,
            DhcpOption::ClientIdentifier(_) => 60,
            DhcpOption::DomainSearch(_) => 119,
            DhcpOption::ClasslessRoutes(_) => 121,
            DhcpOption::Unknown(x, _) => x,
        }
    }

    fn get_size(&self) -> u8 {
        #![allow(unknown_lints,match_same_arms)]
        match *self {
            DhcpOption::SubnetMask(_) => 4,
            DhcpOption::Router(ref vec) | DhcpOption::DomainNameServer(ref vec) => 4 * vec.len() as u8,
            DhcpOption::Hostname(ref str) | DhcpOption::DomainName(ref str) => str.as_bytes().len() as u8,
            DhcpOption::BroadcastAddress(_) | DhcpOption::LeaseTime(_) | DhcpOption::AddressRequest(_) => 4,
            DhcpOption::MessageType(_) => 1,
            DhcpOption::ServerIdentifier(_) => 4,
            DhcpOption::Message(ref str) => str.as_bytes().len() as u8,
            DhcpOption::RenewalTime(_) | DhcpOption::RebindingTime(_) => 4,
            DhcpOption::ClientIdentifier(ref val) => val.len() as u8,
            DhcpOption::DomainSearch(ref val) => val.byte_len() as u8,
            DhcpOption::ClasslessRoutes(ref vec) => vec.iter().fold(0, |v, r| v + r.get_size()),
            DhcpOption::Unknown(_, ref b) => (*b).len() as u8,
        }
    }

    fn push_value(&self, buffer: &mut Vec<u8>) {
        #![allow(unknown_lints,match_same_arms)]
        match *self {
            DhcpOption::SubnetMask(ref mask) => mask.push_to(buffer),
            DhcpOption::Router(ref vec) | DhcpOption::DomainNameServer(ref vec) => {
                for router in vec.iter() {
                    router.push_to(buffer);
                }
            }
            DhcpOption::Hostname(ref str) | DhcpOption::DomainName(ref str) => buffer.extend(str.as_bytes().iter()),
            DhcpOption::BroadcastAddress(ref ip) => ip.push_to(buffer),
            DhcpOption::LeaseTime(l) =>
                buffer.write_u32::<NetworkEndian>(l).unwrap(),
            DhcpOption::AddressRequest(ref ip) => ip.push_to(buffer),
            DhcpOption::MessageType(ref t) => t.push_value(buffer),
            DhcpOption::ServerIdentifier(ref ip) => ip.push_to(buffer),
            DhcpOption::Message(ref str) => buffer.extend(str.as_bytes().iter()),
            DhcpOption::RenewalTime(t) =>
                buffer.write_u32::<NetworkEndian>(t).unwrap(),
            DhcpOption::RebindingTime(t) =>
                buffer.write_u32::<NetworkEndian>(t).unwrap(),
            DhcpOption::ClientIdentifier(ref ci) =>
                buffer.extend(ci.iter()),
            DhcpOption::DomainSearch(ref val) => val.serialize_onto(buffer),
            DhcpOption::ClasslessRoutes(ref routes) => {
                    for route in routes.iter() {
                        route.push_to(buffer);
                    }
                },
            DhcpOption::Unknown(_, ref data) =>
                buffer.extend(data.iter()),
        }
    }

    fn push_to(&self, buffer: &mut Vec<u8>) {
        buffer.push(self.get_type());
        buffer.push(self.get_size());
        self.push_value(buffer);
    }

    fn ipv4s_from_buffer(buffer: &[u8]) -> Result<Box<[Ipv4Addr]>, String> {
        if buffer.len() % 4 != 0 {
            return Err(String::from("Buffer size for vector of IPv4Addresses was not a multiple of 4"));
        }
        let mut ret = Vec::with_capacity(buffer.len() / 4);
        for i in 0..(buffer.len() as usize / 4) {
            let addr = Ipv4Addr::from_buffer(&buffer[4 * i..]);
            ret.push(addr)
        }
        Ok(ret.into_boxed_slice())
    }

    fn string_from_buffer(buffer: &[u8]) -> Result<String, String> {
        match String::from_utf8(Vec::from(buffer)) {
            Ok(s) => Ok(s),
            Err(e) => Err(format!("Failed to decode string: {}", e)),
        }
    }

    fn ipv4_from_buffer(buffer: &[u8]) -> Result<Ipv4Addr, String> {
        if buffer.len() != 4 {
            return Err(String::from("Buffer for single IPv4Address didn't have a size of 4"));
        }

        Ok(Ipv4Addr::from_buffer(buffer))
    }

    fn u32_from_buffer(buffer: &[u8]) -> Result<u32, String> {
        if buffer.len() != 4 {
            return Err("Subnetmask DHCP option size wasn't 4".into());
        }

        Ok(NetworkEndian::read_u32(buffer))
    }

    fn classless_routes_from_buffer(buffer: &[u8]) -> Result<Self, String> {
        let len = buffer.len();
        let mut i = 0;
        let mut ret = Vec::new();

        loop {
            if i == len as usize {
                break;
            }
            let route = ClasslessRoute::from_buffer(&buffer[i..])?;
            i += route.get_size() as usize;
            ret.push(route);
        }

        Ok(DhcpOption::ClasslessRoutes(ret.into_boxed_slice()))
    }

    fn bytes_from_buffer(buffer: &[u8]) -> Box<[u8]> {
        Vec::from(buffer).into_boxed_slice()
    }


    fn from_buffer(variant: u8, buffer: &[u8]) -> Result<Self, String> {
        match variant {
            1  => Ok(DhcpOption::SubnetMask(Self::ipv4_from_buffer(buffer)?)),
            3  => Ok(DhcpOption::Router(Self::ipv4s_from_buffer(buffer)?)),
            6  => Ok(DhcpOption::DomainNameServer(Self::ipv4s_from_buffer(buffer)?)),
            12 => Ok(DhcpOption::Hostname(Self::string_from_buffer(buffer)?)),
            15 => Ok(DhcpOption::DomainName(Self::string_from_buffer(buffer)?)),
            28 => Ok(DhcpOption::BroadcastAddress(Self::ipv4_from_buffer(buffer)?)),
            50 => Ok(DhcpOption::AddressRequest(Self::ipv4_from_buffer(buffer)?)),
            51 => Ok(DhcpOption::LeaseTime(Self::u32_from_buffer(buffer)?)),
            53 => Ok(DhcpOption::MessageType(PacketType::from_value(buffer[0])?)),
            54 => Ok(DhcpOption::ServerIdentifier(Self::ipv4_from_buffer(buffer)?)),
            56 => Ok(DhcpOption::Message(Self::string_from_buffer(buffer)?)),
            58 => Ok(DhcpOption::RenewalTime(Self::u32_from_buffer(buffer)?)),
            59 => Ok(DhcpOption::RebindingTime(Self::u32_from_buffer(buffer)?)),
            60 => Ok(DhcpOption::ClientIdentifier(Self::bytes_from_buffer(buffer))),
            119=> Ok(DhcpOption::DomainSearch(DomainNames::deserialize_from(buffer)?)),
            121=> Self::classless_routes_from_buffer(buffer),
            _  => Ok(DhcpOption::Unknown(variant, Self::bytes_from_buffer(buffer))),
        }
    }

    fn is_message_type(&self) -> bool {
        match *self {
            DhcpOption::MessageType(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DhcpFlags {
    Broadcast
}

#[cfg(test)]
impl Arbitrary for DhcpFlags {
    fn arbitrary<G: Gen>(_: &mut G) -> Self {
        DhcpFlags::Broadcast
    }
}

impl DhcpFlags {
    fn get_value(&self) -> u16{
        match *self {
            DhcpFlags::Broadcast => 0x8000,
        }
    }

    fn from_buffer(buffer: &[u8]) -> Result<Vec<Self>, String> {
        if (buffer[0] & 0x80) != 0 {
            Ok(vec![DhcpFlags::Broadcast])
        } else {
            Ok(Vec::new())
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhcpPacket<Hw> {
    pub packet_type: PacketType,
    pub xid: u32,
    pub seconds: u16,
    pub client_addr: Option<Ipv4Addr>,
    pub your_addr: Option<Ipv4Addr>,
    pub server_addr: Option<Ipv4Addr>,
    pub gateway_addr: Option<Ipv4Addr>,
    pub client_hwaddr: Hw,
    pub options: Vec<DhcpOption>,
    pub flags: Vec<DhcpFlags>,
}

impl<Hw: PartialEq> PartialEq for DhcpPacket<Hw> {
    fn eq(&self, rhs: &Self) -> bool {
        self.packet_type == rhs.packet_type
            && self.xid == rhs.xid
            && self.seconds == rhs.seconds
            && self.client_addr == rhs.client_addr
            && self.your_addr == rhs.your_addr
            && self.server_addr == rhs.server_addr
            && self.gateway_addr == rhs.gateway_addr
            && self.client_hwaddr == rhs.client_hwaddr
            && self.flags == rhs.flags
            // This isn't the most efficient, but the Eq instance should only ever be used for
            // testing either way, so I really don't care much about it
            && self.options.iter().all(|opt| rhs.options.contains(opt))
            && rhs.options.iter().all(|opt| self.options.contains(opt))
    }
}

#[cfg(test)]
impl<Hw: Arbitrary> Arbitrary for DhcpPacket<Hw> {
    fn arbitrary<G: Gen>(gen: &mut G) -> Self {
        let flags = if Arbitrary::arbitrary(gen) {
                vec![DhcpFlags::Broadcast]
            } else {
                Vec::new()
            };

        let options: Vec<DhcpOption> = Arbitrary::arbitrary(gen);
        let mut opts: Vec<DhcpOption>= options.into_iter().filter(|opt| !opt.is_message_type()).collect();
        opts.sort_unstable_by_key(|opt| opt.get_type());
        opts.dedup_by_key(|opt| opt.get_type());

        DhcpPacket {
            packet_type: Arbitrary::arbitrary(gen),
            xid: Arbitrary::arbitrary(gen),
            seconds: Arbitrary::arbitrary(gen),
            client_addr: Arbitrary::arbitrary(gen),
            your_addr: Arbitrary::arbitrary(gen),
            server_addr: Arbitrary::arbitrary(gen),
            gateway_addr: Arbitrary::arbitrary(gen),
            client_hwaddr: Arbitrary::arbitrary(gen),
            options: opts,
            flags: flags,
        }
    }
}

impl<Hw: HwAddr> DhcpPacket<Hw> {
    fn push_flags(&self, buffer: &mut Vec<u8>) {
        let value = self.flags.iter().fold(0, |acc, flag| acc |
flag.get_value());
        buffer.write_u16::<NetworkEndian>(value).unwrap();
    }

    fn push_ip(ip: &Option<Ipv4Addr>, buffer: &mut Vec<u8>) {
        match *ip {
            None => buffer.extend([0, 0, 0, 0,].iter()),
            Some(ref x) => x.push_to(buffer)
        }
    }

    pub fn serialize_with(&self, buffer: &mut Vec<u8>) {
        /* Static-ish foo */
        buffer.push(self.packet_type.get_op());
        buffer.push(Hw::hwtype());
        buffer.push(Hw::size());
        buffer.push(0);

        buffer.write_u32::<NetworkEndian>(self.xid).unwrap();
        buffer.write_u16::<NetworkEndian>(self.seconds).unwrap();
        self.push_flags(buffer);

        /* addresses */
        Self::push_ip(&self.client_addr, buffer);
        Self::push_ip(&self.your_addr, buffer);
        Self::push_ip(&self.server_addr, buffer);
        Self::push_ip(&self.gateway_addr, buffer);

        /* Fill the hw addr and pad */
        self.client_hwaddr.push_to(buffer);
        buffer.extend(iter::repeat(0).take(16 - Hw::size() as usize));

        /* bootfile/next server fields */
        buffer.extend(iter::repeat(0).take(192));

        /* Magic cookie */
        buffer.write_u32::<NetworkEndian>(0x63_82_53_63).unwrap();

        self.packet_type.push_to(buffer);

        for option in &self.options {
            option.push_to(buffer);
        }

        buffer.push(0xff);
    }

    #[cfg(test)]
    fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(1500);
        self.serialize_with(&mut buffer);
        return buffer;
    }

    fn get_ip(buffer: &[u8]) -> Option<Ipv4Addr> {
        let ip = Ipv4Addr::from_buffer(buffer);
        if ip == Ipv4Addr::new(0, 0, 0, 0) {
            None
        } else {
            Some(ip)
        }
    }

    fn get_options(buffer: &[u8]) -> Result<Vec<DhcpOption>, String> {
        let mut map = HashMap::new();
        let mut i = 0;
        loop {
            let opt = match buffer.get(i) {
                    Some(x) => *x,
                    None => {return Err(String::from("Buffer ended before without end option"));},
                };
            // This is the end mark!
            if opt == 255 {
                break;
            }
            // This is the 0 option, just advance over it
            if opt == 0 {
                i += 1;
                continue;
            }

            // This is where it get's interesting :)
            let len = match buffer.get(i + 1) {
                    None => {return Err(String::from("Couldn't read option length because buffer was too short"));},
                    Some(x) => *x as usize,
                };

            if buffer.len() < len + 2 + i {
                return Err(String::from("Option length is larger than buffer left to parse"));
            }

            let current = &buffer[i + 2..i + 2 + len];
            map.entry(opt).or_insert_with(Vec::new).extend_from_slice(current);
            i += len + 2;

        }

        let mut ret = Vec::with_capacity(map.len());
        for (opt, buf) in map {
            let opt = DhcpOption::from_buffer(opt, buf.as_slice())?;
            ret.push(opt);
        }

        Ok(ret)
    }

    pub fn deserialize(buffer: &[u8]) -> Result<Self, String> {
        let cookie_pos = 236;
        if buffer.len() < cookie_pos + 5 {
            return Err(String::from("Message to short to contain dhcp"));
        }
        let cookie = NetworkEndian::read_u32(&buffer[cookie_pos..]);
        if cookie != 0x63_82_53_63 {
            return Err(String::from("Message didn't contain the DHCP magic cookie"));
        }

        let htype = buffer[1];
        let hlen = buffer[2];

        if !((htype == 0 && hlen == 0) || (hlen == Hw::size() && htype == Hw::hwtype())) {
            return Err(String::from("Message was for the wrong hardware type"));
        }


        let xid = NetworkEndian::read_u32(&buffer[4..]);
        let seconds = NetworkEndian::read_u16(&buffer[8..]);
        let flags = DhcpFlags::from_buffer(&buffer[10..])?;

        let client_addr = Self::get_ip(&buffer[12..]);
        let your_addr = Self::get_ip(&buffer[16..]);
        let server_addr = Self::get_ip(&buffer[20..]);
        let gateway_addr = Self::get_ip(&buffer[24..]);

        let client_hwaddr = Hw::from_buffer(&buffer[28..]);
        let options = Self::get_options(&buffer[cookie_pos + 4..])?;
        let packet_type;

        {
            let msg_type = options.iter().find(|opt| opt.is_message_type());

            packet_type = match msg_type {
                Some(&DhcpOption::MessageType(ref t)) => Ok(*t),
                _ => Err(String::from("Couldn't find message type dhcp option")),
                }?;
        }

        Ok(DhcpPacket{
            packet_type: packet_type,
            xid: xid,
            seconds: seconds,
            client_addr: client_addr,
            your_addr: your_addr,
            server_addr: server_addr,
            gateway_addr: gateway_addr,
            client_hwaddr: client_hwaddr,
            flags: flags,
            options: options.into_iter().filter(|opt| !opt.is_message_type()).collect(),
            })
    }
}

impl<Hw: HwAddr> Serializeable for DhcpPacket<Hw> {

    fn serialize_onto(&self, buffer: &mut Vec<u8>) {
        self.serialize_with(buffer);
    }

    fn deserialize_from(buffer: &[u8]) -> Result<Self, String> {
        Self::deserialize(buffer)
    }
}

#[cfg(test)]
mod tests {
    use frame::ethernet::EthernetAddr;

    use packet::PacketType;
    use packet::ClasslessRoute;
    use packet::DhcpOption;
    use packet::DhcpPacket;

    quickcheck! {
        fn serialize_type(packet: PacketType) -> bool {
            let mut buffer = Vec::new();
            packet.push_to(&mut buffer);
            let de = PacketType::from_buffer(buffer.as_slice());
            return Ok(packet) == de;
        }

        fn serialize_classless(route: ClasslessRoute) -> bool {
            let mut buffer = Vec::new();
            route.push_to(&mut buffer);
            let de = ClasslessRoute::from_buffer(buffer.as_slice());
            return Ok(route) == de;
        }

        fn serialize_dhcpoption(opt: DhcpOption) -> bool {
            let mut buffer = Vec::new();
            opt.push_to(&mut buffer);
            let de = DhcpOption::from_buffer(opt.get_type(), &(buffer.as_slice()[2..]));
            return Ok(opt) == de;
        }

        fn serialize_packet(packet: DhcpPacket<EthernetAddr>) -> bool {
            let buffer = packet.serialize();
            let de = DhcpPacket::deserialize(buffer.as_slice());
            println!("{:?}", de);
            return Ok(packet) == de;
        }
    }
}
