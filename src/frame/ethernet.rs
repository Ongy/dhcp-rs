extern crate byteorder;

use self::byteorder::{WriteBytesExt, NetworkEndian, ByteOrder};
use std::vec::Vec;
use serialize::Serializeable;

#[derive(Debug, Clone, Copy)] //deduplicate
pub struct EthernetAddr (pub [u8;6]);

#[derive(Debug)]
pub struct Ethernet<P> {
	pub dst: EthernetAddr,
	pub src: EthernetAddr,
	pub eth_type: u16,
	pub payload: P
}

impl<P: Serializeable> Serializeable for Ethernet<P> {
	fn serialize_onto(&self, buffer: &mut Vec<u8>) {
		buffer.extend(self.dst.0.iter());
		buffer.extend(self.src.0.iter());
		buffer.write_u16::<NetworkEndian>(self.eth_type).unwrap();
		self.payload.serialize_onto(buffer);
	}

	fn deserialize_from(buffer: &[u8]) -> Result<Self, String> {
		if buffer.len() < 14 {
			return Err("Buffer to small, can't decode ethernet header".into());
		}

		let dst = [buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]];
		let src = [buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11]];
		let eth_type = NetworkEndian::read_u16(&buffer[12..]);
		let payload = P::deserialize_from(&buffer[14..])?;

		return Ok(Ethernet{src: EthernetAddr(src), dst: EthernetAddr(dst), eth_type: eth_type, payload: payload})
	}
}
