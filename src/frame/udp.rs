extern crate byteorder;
extern crate pnet;

use self::byteorder::{WriteBytesExt, NetworkEndian, ByteOrder};
//TODO: use self::pnet::util::checksum;

use std::vec::Vec;
use serialize::{Serializeable, HasCode};


#[derive(Debug)]
pub struct UDP<P> {
	pub src: u16,
	pub dst: u16,
	pub payload: P,
}

impl<P: Serializeable> Serializeable for UDP<P> {
	fn serialize_onto(&self, buffer: &mut Vec<u8>) {
		buffer.write_u16::<NetworkEndian>(self.src).unwrap();
		buffer.write_u16::<NetworkEndian>(self.dst).unwrap();
		let len_pos = buffer.len();
		buffer.write_u16::<NetworkEndian>(0).unwrap();
		buffer.write_u16::<NetworkEndian>(0).unwrap();

		let pre = buffer.len();
		self.payload.serialize_onto(buffer);
		let payload_len = buffer.len() - pre;

		NetworkEndian::write_u16_into(&[8 + payload_len as u16], &mut buffer.as_mut_slice()[len_pos..len_pos + 2]);
	}

	fn deserialize_from(buffer: &[u8]) -> Result<Self, String> {
		if buffer.len() < 8 {
			return Err("Buffer is too small. Minimum buffer length to decode udp is 8 bytes.".into());
		}
		let src = NetworkEndian::read_u16(&buffer[0..]);
		let dst = NetworkEndian::read_u16(&buffer[2..]);
		let len = NetworkEndian::read_u16(&buffer[4..]);

		if buffer.len() < len as usize {
			return Err("Buffer is too small. Can't contain entire UDP datagram".into());
		}

		let payload = P::deserialize_from(&buffer[8..len as usize])?;

		return Ok(Self{src: src, dst: dst, payload: payload});
	}
}

impl<P> HasCode for UDP<P> {
    type CodeType=u8;

    fn get_code() -> u8 { 17 }
}
