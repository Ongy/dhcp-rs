extern crate byteorder;

use self::byteorder::{NativeEndian, WriteBytesExt, NetworkEndian, ByteOrder};

use std::iter;
use std::vec::Vec;
use std::option::Option;
use std::result::Result;

#[derive(Debug, Clone, Copy)]
pub enum PacketType {
	Discover,
	Offer,
	Request,
	Ack,
	Nack
}

impl PacketType {
	fn push_value(&self, buffer: &mut Vec<u8>) {
		buffer.push(match self {
			&PacketType::Discover => 0x1,
			&PacketType::Offer => 0x2,
			&PacketType::Request => 0x3,
			&PacketType::Ack => 0x5,
			&PacketType::Nack => 0x6
		});
	}

	fn push_to(&self, buffer: &mut Vec<u8>) {
		buffer.push(53);
		buffer.push(0x1);
		self.push_value(buffer);
	}

	fn from_buffer(buffer: &[u8]) -> Result<Self, String> {
		if buffer[0] != 53 {
			return Err(format!("Encountered unexpected option type for dhcp packet type: {}", buffer[0]));
		}

		if buffer[1] != 0x1 {
			return Err(format!("Encountered unexpected option length for dhcp packet type: {}", buffer[1]));
		}

		match buffer[2] {
			0x1 => Ok(PacketType::Discover),
			0x2 => Ok(PacketType::Offer),
			0x3 => Ok(PacketType::Request),
			0x5 => Ok(PacketType::Ack),
			0x6 => Ok(PacketType::Nack),
			x => Err(format!("Encountered unexpected value for dhcp packet type: {}", x))
		}
	}

	fn get_op(&self) -> u8 {
		match self {
			&PacketType::Discover => 0x1,
			&PacketType::Offer => 0x2,
			&PacketType::Request => 0x1,
			&PacketType::Ack => 0x2,
			&PacketType::Nack => 0x2
		}
	}
}

pub trait HwAddr {
	fn size() -> u8;
	fn hwtype() -> u8;
	fn push_to(&self, &mut Vec<u8>);
	fn from_buffer(& [u8]) -> Self;
}

#[derive(Debug)] //deduplicate
pub struct EthernetAddr (pub [u8;6]);

impl HwAddr for EthernetAddr {
	fn size() -> u8 { 6 }

	fn hwtype() -> u8 { 0x1 }

	fn push_to(&self, buffer: &mut Vec<u8>) {
		buffer.extend(self.0.iter());
	}

	fn from_buffer(buffer: & [u8]) -> Self {
		let mut array = [0; 6];
		array.copy_from_slice(&buffer[..6]);
		return EthernetAddr(array);
	}
}

#[derive(Debug, PartialEq, Eq)]
pub struct IPv4Addr (pub [u8;4]);

impl IPv4Addr {
	fn push_to(&self, buffer: &mut Vec<u8>) {
		buffer.extend(self.0.iter());
	}

	fn from_buffer(buffer: &[u8]) -> Self {
		let mut array = [0; 4];
		array.copy_from_slice(&buffer[..4]);
		return IPv4Addr(array);
	}
}

#[derive(Debug)]
pub enum DhcpOption {
	SubnetMask(IPv4Addr), //This should probably be a better type
	Router(Vec<IPv4Addr>),
	MessageType(PacketType)
}

impl DhcpOption {
	fn get_type(&self) -> u8 {
		match self {
			&DhcpOption::SubnetMask(_) => 0x1,
			&DhcpOption::Router(_) => 0x3,
			&DhcpOption::MessageType(_) => 53,
		}
	}

	fn get_size(&self) -> u8 {
		match self {
			&DhcpOption::SubnetMask(_) => 4,
			&DhcpOption::Router(ref vec) => 4 * vec.len() as u8,
			&DhcpOption::MessageType(_) => 1,
		}
	}

	fn push_value(&self, buffer: &mut Vec<u8>) {
		match self {
			&DhcpOption::SubnetMask(ref mask) => mask.push_to(buffer),
			&DhcpOption::Router(ref vec) => {
				for ref router in vec.iter() {
					router.push_to(buffer);
				}
			}
			&DhcpOption::MessageType(ref t) => t.push_value(buffer),
		}
	}

	fn push_to(&self, buffer: &mut Vec<u8>) {
		buffer.push(self.get_type());
		buffer.push(self.get_size());
		self.push_value(buffer);
	}

	fn subnetmask_from_buffer(buffer: &[u8]) -> Result<Self, String> {
		if buffer[1] != 4 {
			return Err("Subnetmask DHCP option size wasn't 4".into());
		}
		let addr = IPv4Addr::from_buffer(&buffer[2..]);
		return Ok(DhcpOption::SubnetMask(addr));
	}

	fn router_from_buffer(buffer: &[u8]) -> Result<Self, String> {
		if buffer[1] % 4 != 0 {
			return Err("Router DHCP option size wasn't a multiple of 4".into());
		}
		let mut ret = Vec::with_capacity(buffer[1] as usize / 4);
		for i in 0..(buffer[1] as usize / 4) {
			let addr = IPv4Addr::from_buffer(&buffer[2 + 4 * i..]);
			ret.push(addr)
		}
		return Ok(DhcpOption::Router(ret));
	}

	fn from_buffer(buffer: &[u8]) -> Result<Self, String> {
		match buffer[0] {
			1  => Self::subnetmask_from_buffer(buffer),
			3  => Self::router_from_buffer(buffer),
			53 => Ok(DhcpOption::MessageType(PacketType::from_buffer(buffer)?)),
			x  => Err(format!("Unkown option type: {}", x)),
		}
	}

	fn is_message_type(&self) -> bool {
		match self {
			&DhcpOption::MessageType(_) => true,
			_ => false,
		}
	}
}

#[derive(Debug)]
pub enum DhcpFlags {
	Broadcast
}

impl DhcpFlags {
	fn get_value(&self) -> u16{
		match self {
			&DhcpFlags::Broadcast => 0x8000,
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

#[derive(Debug)]
pub struct DhcpPacket<Hw> {
	pub packet_type: PacketType,
	pub xid: u32,
	pub seconds: u16,
	pub client_addr: Option<IPv4Addr>,
	pub your_addr: Option<IPv4Addr>,
	pub server_addr: Option<IPv4Addr>,
	pub gateway_addr: Option<IPv4Addr>,
	pub client_hwaddr: Hw,
	pub options: Vec<DhcpOption>,
	pub flags: Vec<DhcpFlags>,
}

impl<Hw: HwAddr> DhcpPacket<Hw> {
	fn push_flags(&self, buffer: &mut Vec<u8>) {
		let value = self.flags.iter().fold(0, |acc, flag| acc |
flag.get_value());
		buffer.write_u16::<NetworkEndian>(value).unwrap();
	}

	fn push_ip(ip: &Option<IPv4Addr>, buffer: &mut Vec<u8>) {
		match ip {
			&None => buffer.extend([0, 0, 0, 0,].iter()),
			&Some(ref x) => x.push_to(buffer)
		}
	}

	pub fn serialize(&self) -> Vec<u8> {
		let mut buffer = Vec::with_capacity(1500);
		/* Static-ish foo */
		buffer.push(self.packet_type.get_op());
		buffer.push(Hw::hwtype());
		buffer.push(Hw::size());
		buffer.push(0);

		buffer.write_u32::<NativeEndian>(self.xid).unwrap();
		buffer.write_u16::<NetworkEndian>(self.seconds).unwrap();
		self.push_flags(&mut buffer);

		/* addresses */
		Self::push_ip(&self.client_addr, &mut buffer);
		Self::push_ip(&self.your_addr, &mut buffer);
		Self::push_ip(&self.server_addr, &mut buffer);
		Self::push_ip(&self.gateway_addr, &mut buffer);

		/* Fill the hw addr and pad */
		self.client_hwaddr.push_to(&mut buffer);
		buffer.extend(iter::repeat(0).take(16 - Hw::size() as usize));

		/* bootfile/next server fields */
		buffer.extend(iter::repeat(0).take(192));

		/* Magic cookie */
		buffer.write_u32::<NetworkEndian>(0x63825363).unwrap();

		self.packet_type.push_to(&mut buffer);

		for ref option in self.options.iter() {
			option.push_to(&mut buffer);
		}

		buffer.push(0xff);
		return buffer;
	}

	fn get_ip(buffer: &[u8]) -> Option<IPv4Addr> {
		let ip = IPv4Addr::from_buffer(buffer);
		if ip == IPv4Addr([0, 0, 0, 0]) {
			return None;
		} else {
			return Some(ip);
		}
	}

	fn get_options(buffer: &[u8]) -> Result<Vec<DhcpOption>, String> {
		let mut ret = Vec::new();
		let mut i = 0;
		loop {
			if buffer[i] == 255 {
				break;
			}
			if buffer[i] == 0 {
				i += 1;
				continue;
			}

			let opt = DhcpOption::from_buffer(&buffer[i..])?;
			i += 2 + opt.get_size() as usize;
			ret.push(opt);
		}
		return Ok(ret);
	}

	pub fn deserialize(buffer: &[u8]) -> Result<Self, String> {
		let xid = NetworkEndian::read_u32(&buffer[4..]);
		let seconds = NetworkEndian::read_u16(&buffer[8..]);
		let flags = DhcpFlags::from_buffer(&buffer[10..])?;

		let client_addr = Self::get_ip(&buffer[12..]);
		let your_addr = Self::get_ip(&buffer[16..]);
		let server_addr = Self::get_ip(&buffer[20..]);
		let gateway_addr = Self::get_ip(&buffer[24..]);

		let client_hwaddr = Hw::from_buffer(&buffer[28..]);
		let cookie_pos = 236;
		let options = Self::get_options(&buffer[cookie_pos + 4..])?;
		let packet_type;

		{
			let msg_type = options.iter().find(|opt| opt.is_message_type());

			packet_type = match msg_type {
				Some(&DhcpOption::MessageType(ref t)) => Ok(*t),
				_ => Err(String::from("Couldn't find message type dhcp option")),
				}?;
		}

		return Ok(DhcpPacket{
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
			});
	}
}
