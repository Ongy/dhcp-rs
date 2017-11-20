extern crate byteorder;
extern crate pnet;

use self::byteorder::{NativeEndian, WriteBytesExt, NetworkEndian, ByteOrder};
use self::pnet::util::checksum;

use std::boxed::Box;
use std::vec::Vec;

#[derive(Debug)] //deduplicate
pub struct EthernetAddr (pub [u8;6]);

#[derive(Debug)]
pub struct Ethernet<'a> {
	pub dst: EthernetAddr,
	pub src: EthernetAddr,
	pub eth_type: u16,
	pub payload: &'a [u8]
}

#[derive(Debug)] //deduplicate
pub struct IPv4Addr (pub [u8;4]);

#[derive(Debug)]
pub struct IPv4Packet<'a> {
	pub src: IPv4Addr,
	pub dst: IPv4Addr,
	pub ttl: u8,
	pub protocol: u8,

	pub payload: &'a [u8]
}

#[derive(Debug)]
pub struct UDP<'a> {
	pub src: u16,
	pub dst: u16,
	pub payload: &'a [u8]
}

impl<'a> UDP<'a> {
	pub fn serialize(&self) -> Box<[u8]> {
		let mut buffer = Vec::with_capacity(self.payload.len() + 8);

		buffer.write_u16::<NetworkEndian>(self.src).unwrap();
		buffer.write_u16::<NetworkEndian>(self.dst).unwrap();
		buffer.write_u16::<NetworkEndian>(8 + self.payload.len() as u16).unwrap();
		buffer.write_u16::<NetworkEndian>(0).unwrap();

		buffer.extend(self.payload.iter());

		return buffer.into_boxed_slice();
	}

	pub fn deserialize(buffer: &'a [u8]) -> Result<Self, String> {
		if buffer.len() < 8 {
			return Err("Buffer is too small. Minimum buffer length to decode udp is 8 bytes.".into());
		}
		let src = NetworkEndian::read_u16(&buffer[0..]);
		let dst = NetworkEndian::read_u16(&buffer[2..]);
		let len = NetworkEndian::read_u16(&buffer[4..]);

		if buffer.len() < len as usize {
			return Err("Buffer is too small. Can't contain entire UDP datagram".into());
		}

		return Ok(Self{src: src, dst: dst, payload: &buffer[8..len as usize]});
	}
}

impl<'a> IPv4Packet<'a> {
	pub fn serialize(&self) -> Box<[u8]> {
		let mut buffer = Vec::with_capacity(self.payload.len() + 20);

		/* Version + IHL */
		buffer.push(0x45);
		buffer.push(0);

		buffer.write_u16::<NetworkEndian>(20 + self.payload.len() as u16).unwrap();
		buffer.write_u16::<NetworkEndian>(0).unwrap(); // TODO: Randomize identifier

		/* Do not fragment and no fragment offset */
		buffer.push(0x40);
		buffer.push(0x00);

		buffer.push(self.ttl);
		buffer.push(self.protocol);

		/* First set checksum to 0 */
		buffer.write_u16::<NetworkEndian>(0).unwrap();

		buffer.extend(self.src.0.iter());
		buffer.extend(self.dst.0.iter());

		let checksum = checksum(buffer.as_slice(), 5);

		buffer[10] = (checksum >> 8) as u8;
		buffer[11] = (checksum & 0xFF) as u8;

		buffer.extend(self.payload.iter());

		return buffer.into_boxed_slice();
	}

	pub fn deserialize(buffer: &'a [u8]) -> Result<Self, String> {
		if buffer.len() < 20 {
			return Err("Buffer is too small. Minimum buffer length to decode ip is 20 bytes.".into());
		}
		if buffer[0] & 0xF0 != 0x40 {
			return Err("This is not an IPv4 packet. Will not decode".into());
		}
		if buffer[0] & 0x0F != 0x05 {
			return Err("We don't support decoding ip options yet".into());
		}
		if buffer[6] & 0x20 != 0x00 {
			return Err("We don't support decoding fragmented ip packets".into())
		}

		let ip_len = NetworkEndian::read_u16(&buffer[2..]);
		if buffer.len() < ip_len as usize {
			return Err("The buffer is too small to contain the entire ip packet".into());
		}
		let checksum = checksum(&buffer[..20], 5);

		if (buffer[10] != (checksum >> 8) as u8 || buffer[11] != (checksum & 0xFF) as u8) {
			return Err("IPv4 header checksum validation failed".into());
		}

		let ttl = buffer[8];
		let protocol = buffer[9];

		let src = [buffer[12], buffer[13], buffer[14], buffer[15]];
		let dst = [buffer[16], buffer[17], buffer[18], buffer[19]];

		return Ok(Self{src: IPv4Addr(src), dst: IPv4Addr(dst), ttl: ttl, protocol: protocol, payload: &buffer[20..ip_len as usize]});
	}
}

impl<'a> Ethernet<'a> {
	pub fn serialize(&self) -> Box<[u8]> {
		let mut buffer = Vec::with_capacity(self.payload.len() + 14);
		buffer.extend(self.dst.0.iter());
		buffer.extend(self.src.0.iter());
		buffer.write_u16::<NetworkEndian>(self.eth_type).unwrap();

		buffer.extend(self.payload.iter());

		return buffer.into_boxed_slice();
	}

	pub fn deserialize(buffer: &'a [u8]) -> Result<Self, String> {
		if buffer.len() < 14 {
			return Err("Buffer to small, can't decode ethernet header".into());
		}

		let dst = [buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]];
		let src = [buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11]];
		let eth_type = NetworkEndian::read_u16(&buffer[12..]);

		return Ok(Ethernet{src: EthernetAddr(src), dst: EthernetAddr(dst), eth_type: eth_type, payload: &buffer[14..]})
	}
}
