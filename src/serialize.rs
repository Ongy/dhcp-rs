use std::vec::Vec;
use std::result::Result;
use std::boxed::Box;
use std::marker::Sized;

pub trait Serializeable
	where Self: Sized {

	fn serialize_onto(&self, &mut Vec<u8>);
	fn deserialize_from(&[u8]) -> Result<Self, String>;
}

pub trait HasCode {
    type CodeType;
    fn get_code() -> Self::CodeType;
}

pub fn serialize<P:Serializeable>(obj: &P) -> Box<[u8]> {
	let mut buffer = Vec::with_capacity(1514);
	obj.serialize_onto(&mut buffer);
	buffer.into_boxed_slice()
}

pub fn deserialize<P:Serializeable>(buffer: &[u8]) -> Result<P, String> {
	P::deserialize_from(buffer)
}
