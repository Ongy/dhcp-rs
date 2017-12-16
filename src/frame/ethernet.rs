extern crate byteorder;
extern crate rs_config;

use rs_config::{ConfigProvider, ConfigAble, ParseError};

#[cfg(test)]
use quickcheck::Arbitrary;
#[cfg(test)]
use quickcheck::Gen;

use std;
use std::str::FromStr;
use std::fmt::Write;
use self::byteorder::{WriteBytesExt, NetworkEndian, ByteOrder};
use std::vec::Vec;

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

use serialize::{HasCode, Serializeable};
use ::pnet::datalink::MacAddr;

extern {
    fn ether_aton_r(asc: *const u8, addr: *mut EthernetAddr) -> *mut EthernetAddr;
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct EthernetAddr (pub [u8;6]);

impl std::fmt::Display for EthernetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for i in 0..6 {
            write!(f, "{:02x}", self.0[i])?;
            if i != 5 {
                f.write_char(':')?;
            }
        }

        Ok(())
    }
}

impl FromStr for EthernetAddr {
    type Err=String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let osstr = OsString::from(s);
        let vec = osstr.into_vec();
        if vec.len() > 18 {
            return Err(format!("\"{}\" is too long to be parsed as valid EthernetAddr", s));
        }
        let mut ret = EthernetAddr([0; 6]);

        unsafe {
            if ether_aton_r(vec.as_ptr(), &mut ret as *mut EthernetAddr).is_null() {
                return Err(format!("Could not parse \"{}\" as EthernetAddr", s));
            }
        }

        Ok(ret)
    }
}

impl ConfigAble for EthernetAddr {
    fn get_format<F>(_: &mut std::collections::HashSet<String>, fun: &mut F)
        where F: FnMut(&str) {
        fun("EthernetAddr: xx:xx:xx:xx:xx:xx");
    }

    fn parse_from<F>(provider: &mut ConfigProvider, fun: &mut F) -> Result<Self, ParseError>
        where F: FnMut(String) {
        if let Some(txt) = provider.get_next() {
            let used: String = txt.chars().take_while(|c| c.is_digit(16) || *c == ':').collect();
            provider.consume(used.len(), fun)?;
            return match EthernetAddr::from_str(used.as_str()) {
                Ok(x) => Ok(x),
                Err(e) => {
                    fun(e);
                    Err(ParseError::Recoverable)
                },
            }
        }

        fun(String::from("At end of file :("));
        Err(ParseError::Final)
    }

    fn get_name() -> &'static str { "EternetAddr" }

    fn get_default() -> Result<Self, ()> { Err(()) }

}

impl<'a> From<&'a MacAddr> for EthernetAddr {
    fn from(arg: &'a MacAddr) -> Self {
        EthernetAddr([arg.0, arg.1, arg.2, arg.3, arg.4, arg.5])
    }
}

#[derive(Debug)]
pub struct Ethernet<P> {
	pub dst: EthernetAddr,
	pub src: EthernetAddr,
	pub payload: P
}

impl<P: Serializeable + HasCode<CodeType=u16>> Serializeable for Ethernet<P> {
	fn serialize_onto(&self, buffer: &mut Vec<u8>) {
		buffer.extend(self.dst.0.iter());
		buffer.extend(self.src.0.iter());
		buffer.write_u16::<NetworkEndian>(P::get_code()).unwrap();
		self.payload.serialize_onto(buffer);
	}

	fn deserialize_from(buffer: &[u8]) -> Result<Self, String> {
		if buffer.len() < 14 {
			return Err("Buffer to small, can't decode ethernet header".into());
		}

		let eth_type = NetworkEndian::read_u16(&buffer[12..]);

        if eth_type != P::get_code() {
            return Err(String::from("The ethernet payload didn't have the correct type"));
        }

		let dst = [buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]];
		let src = [buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11]];
		let payload = P::deserialize_from(&buffer[14..])?;

		Ok(Ethernet{src: EthernetAddr(src), dst: EthernetAddr(dst), payload: payload})
	}
}

#[cfg(test)]
impl Arbitrary for EthernetAddr {
    fn arbitrary<G: Gen>(gen: &mut G) -> Self {
        let vals: (u8, u8, u8, u8, u8, u8) = Arbitrary::arbitrary(gen);
        EthernetAddr([vals.0, vals.1, vals.2, vals.3, vals.4, vals.5])
    }
}
