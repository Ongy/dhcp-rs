extern crate byteorder;
extern crate pnet;

use self::byteorder::{NativeEndian, WriteBytesExt, NetworkEndian};
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
}
