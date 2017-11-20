extern crate byteorder;

use self::byteorder::{NativeEndian, WriteBytesExt, NetworkEndian};

use std::iter;
use std::vec::Vec;
use std::option::Option;
use std::result::Result;

#[derive(Debug)]
pub enum PacketType {
	Discover,
	Offer,
	Request,
	Ack,
	Nack
}

impl PacketType {
	fn push_to(&self, buffer: &mut Vec<u8>) {
		buffer.push(53);
		buffer.push(0x1);
		buffer.push(match self {
			&PacketType::Discover => 0x1,
			&PacketType::Offer => 0x2,
			&PacketType::Request => 0x3,
			&PacketType::Ack => 0x5,
			&PacketType::Nack => 0x6
		});
	}

	fn from_buffer(buffer: &[u8]) -> Result<Self, String> {
		if buffer[0] != 53 {
			return Err(format!("Encountered unexpected option type for dhcp packet type: {}", buffer[0]));
		}

		if buffer[1] != 0x1 {
			return Err(format!("Encountered unexpected option length for dhcp packet type: {}", buffer[1]));
		}

		match buffer[2] {
			0x0 => Ok(PacketType::Discover),
			0x1 => Ok(PacketType::Offer),
			0x2 => Ok(PacketType::Request),
			0x4 => Ok(PacketType::Ack),
			0x5 => Ok(PacketType::Nack),
			x => Err(format!("Encountered unexpected value for dhcp packet type: {}", buffer[2]))
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

trait HwAddr {
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
		array.copy_from_slice(buffer);
		return EthernetAddr(array);
	}
}

#[derive(Debug)]
pub struct IpAddr (pub [u8;4]);

impl IpAddr {
	fn push_to(&self, buffer: &mut Vec<u8>) {
		buffer.extend(self.0.iter());
	}
}

#[derive(Debug)]
pub enum DhcpOption {
	SubnetMask(IpAddr), //This should probably be a better type
	Router(Vec<IpAddr>)
}

impl DhcpOption {
	fn get_type(&self) -> u8 {
		match self {
			&DhcpOption::SubnetMask(_) => 0x1,
			&DhcpOption::Router(_) => 0x3
		}
	}

	fn get_size(&self) -> u8 {
		match self {
			&DhcpOption::SubnetMask(_) => 4,
			&DhcpOption::Router(ref vec) => 4 * vec.len() as u8
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
		}
	}

	fn push_to(&self, buffer: &mut Vec<u8>) {
		buffer.push(self.get_type());
		buffer.push(self.get_size());
		self.push_value(buffer);
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

	fn from_buffer(buffer: &mut[u8]) -> Result<Vec<Self>, String> {
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
	pub client_addr: Option<IpAddr>,
	pub your_addr: Option<IpAddr>,
	pub server_addr: Option<IpAddr>,
	pub gateway_addr: Option<IpAddr>,
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

	fn push_ip(ip: &Option<IpAddr>, buffer: &mut Vec<u8>) {
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
}
