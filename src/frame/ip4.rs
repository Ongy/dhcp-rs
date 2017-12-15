extern crate byteorder;
extern crate pnet;

use self::byteorder::{WriteBytesExt, NetworkEndian, ByteOrder};
use self::pnet::util::checksum;

use std::vec::Vec;
use serialize::{Serializeable, HasCode};

use std::convert::Into;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct IPv4Packet<P> {
	pub src: Ipv4Addr,
	pub dst: Ipv4Addr,
	pub ttl: u8,

	pub payload: P
}

impl<P: Serializeable + HasCode<CodeType=u8>> Serializeable for IPv4Packet<P> {
	fn serialize_onto(&self, buffer: &mut Vec<u8>) {
		/* Version + IHL */
		let start = buffer.len();
		buffer.push(0x45);
		buffer.push(0);
		let len_pos = buffer.len();

		buffer.write_u16::<NetworkEndian>(0).unwrap();
		buffer.write_u16::<NetworkEndian>(0).unwrap(); // TODO: Randomize identifier

		/* Do not fragment and no fragment offset */
		buffer.push(0x40);
		buffer.push(0x00);

		buffer.push(self.ttl);
		buffer.push(P::get_code());

		/* First set checksum to 0 */
		buffer.write_u16::<NetworkEndian>(0).unwrap();

		buffer.extend(self.src.octets().iter());
		buffer.extend(self.dst.octets().iter());

		let pre = buffer.len();
		self.payload.serialize_onto(buffer);
		let payload_len = buffer.len() - pre;
		NetworkEndian::write_u16_into(&[20 + payload_len as u16], &mut buffer.as_mut_slice()[len_pos..len_pos + 2]);

		let checksum = checksum(&buffer.as_slice()[start..start+20], 5);

		buffer[start + 10] = (checksum >> 8) as u8;
		buffer[start + 11] = (checksum & 0xFF) as u8;

	}

	fn deserialize_from(buffer: &[u8]) -> Result<Self, String> {
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

		if buffer[10] != (checksum >> 8) as u8 || buffer[11] != (checksum & 0xFF) as u8 {
			return Err("IPv4 header checksum validation failed".into());
		}

		let ttl = buffer[8];
		let protocol = buffer[9];

        if protocol != P::get_code() {
            return Err(String::from("IP payload was of the wrong protocol"));
        }

		let src = Ipv4Addr::new(buffer[12], buffer[13], buffer[14], buffer[15]);
		let dst = Ipv4Addr::new(buffer[16], buffer[17], buffer[18], buffer[19]);

		let payload = P::deserialize_from(&buffer[20..ip_len as usize])?;


		return Ok(Self{src: src, dst: dst, ttl: ttl, payload: payload});
	}
}

impl<P> HasCode for IPv4Packet<P> {
    type CodeType=u16;
    fn get_code() -> u16 { 0x0800 }
}
