extern crate time;

pub struct Lease<H, I> {
	pub hw_addr: H,
	pub assigned: I,
	pub client_identifier: Option<Box<[u8]>>,
	pub lease_start: time::Timespec,
	pub lease_duration: u32
}
