extern crate rs_config;
extern crate byteorder;
extern crate pnet;

use rs_config::ConfigAble;

#[cfg(test)]
use quickcheck::Arbitrary;
#[cfg(test)]
use quickcheck::Gen;

use self::byteorder::{WriteBytesExt, NetworkEndian, ByteOrder};
use self::pnet::util::checksum;

use std::vec::Vec;
use serialize::Serializeable;

use std::convert::Into;

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Hash, ConfigAble)]
pub struct IPv4Addr (pub [u8;4]);

impl Into<u32> for IPv4Addr {
    fn into(self) -> u32 {
        NetworkEndian::read_u32(&self.0)
    }
}

impl From<u32> for IPv4Addr {
    fn from(arg: u32) -> Self {
        let mut buffer = [0;4];
        NetworkEndian::write_u32(&mut buffer, arg);
        IPv4Addr(buffer)
    }
}

#[derive(Debug)]
pub struct IPv4Packet<P> {
	pub src: IPv4Addr,
	pub dst: IPv4Addr,
	pub ttl: u8,
	pub protocol: u8,

	pub payload: P
}

impl<P: Serializeable> Serializeable for IPv4Packet<P> {
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
		buffer.push(self.protocol);

		/* First set checksum to 0 */
		buffer.write_u16::<NetworkEndian>(0).unwrap();

		buffer.extend(self.src.0.iter());
		buffer.extend(self.dst.0.iter());

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

		let src = [buffer[12], buffer[13], buffer[14], buffer[15]];
		let dst = [buffer[16], buffer[17], buffer[18], buffer[19]];

		let payload = P::deserialize_from(&buffer[20..ip_len as usize])?;


		return Ok(Self{src: IPv4Addr(src), dst: IPv4Addr(dst), ttl: ttl, protocol: protocol, payload: payload});
	}
}

#[cfg(test)]
impl Arbitrary for IPv4Addr {
    fn arbitrary<G: Gen>(gen: &mut G) -> Self {
        let vals: (u8, u8, u8, u8) = Arbitrary::arbitrary(gen);
        IPv4Addr([vals.0, vals.1, vals.2, vals.3])
    }
}
