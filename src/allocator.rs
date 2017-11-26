extern crate time;
use std::iter::Iterator;

extern crate serde;
extern crate serde_json;

use self::serde::Serialize;

use lease;
use pool;

use frame::ethernet::EthernetAddr;
use frame::ip4::IPv4Addr;


// For now this is a pure ipv4 <-> ethernet allocator
pub struct Allocator {
	allocations: Vec<lease::Allocation<EthernetAddr, IPv4Addr>>,
	leases: Vec<lease::Lease<EthernetAddr, IPv4Addr>>,
	address_pool: pool::IPPool,
}

impl Allocator {
	/* Get the allocations we could reuse because there's no current lease
	 * for them (which would lock them
	 */
	fn get_viable_allocs(&self) -> Vec<&lease::Allocation<EthernetAddr, IPv4Addr>> {
		return self.allocations.iter().filter(|alloc|
			self.leases.iter().all(|lease|
				!lease.is_for_alloc(alloc))).collect();
	}

	pub fn new(p: pool::IPPool) -> Allocator {
		Allocator { address_pool: p, leases: Vec::new(), allocations: Vec::new() }
	}

	fn find_allocation(&self, client: &lease::Client<EthernetAddr>) -> Option<usize> {
		self.allocations.iter().enumerate().find(|alloc|
&alloc.1.client == client).map(|(i, _)| i)
	}

	// We *may* be out of allocatable addresses
	pub fn allocation_for(&mut self, client: &lease::Client<EthernetAddr>) -> Option<&lease::Allocation<EthernetAddr, IPv4Addr>> {
		let mut pos = self.find_allocation(client);

		if pos.is_none() {
			if let Some(ip) = self.next_ip() {
				let alloc = lease::Allocation{
					assigned: ip,
					client: client.clone(),
					last_seen: lease::SerializeableTime(time::get_time())
					};
				self.allocations.push(alloc);
				pos = Some(self.allocations.len() - 1);
			} else {
				return None;
			}
		}

		return pos.and_then(move |i| self.allocations.get(i));
	}

	pub fn get_requested(&mut self, client: &lease::Client<EthernetAddr>, addr: &IPv4Addr) -> Option<&lease::Allocation<EthernetAddr, IPv4Addr>> {
		let ip = ((addr.0[0] as u32) << 24) + ((addr.0[1] as u32) << 16) + ((addr.0[2] as u32) << 8) + (addr.0[3] as u32);
		let found = self.allocations.iter().enumerate().find(|alloc| &alloc.1.assigned == addr).map(|(i, _)| i);

		if found.is_none() {
			if self.address_pool.is_suitable(ip) {
				self.address_pool.set_used(ip);
				let alloc = lease::Allocation {
					client: client.clone(),
					assigned: addr.clone(),
					last_seen: lease::SerializeableTime(time::get_time())
					};
				self.allocations.push(alloc);
				return self.allocations.last();
			}
		}
		return found.and_then(move |i| self.allocations.get(i));
	}

	pub fn get_allocation(&mut self, client: &lease::Client<EthernetAddr>, addr: Option<IPv4Addr>) -> Option<&lease::Allocation<EthernetAddr, IPv4Addr>> {
		match addr {
			None => self.allocation_for(client),
			Some(x) => self.get_requested(client, &x),
		}
	}


	pub fn seralize_leases(&self) -> String {
		serde_json::to_string(&self.leases).unwrap()
	}

	pub fn seralize_allocs(&self) -> String {
		serde_json::to_string(&self.allocations).unwrap()
	}

	fn next_ip(&mut self) -> Option<IPv4Addr> {
		let tmp = self.address_pool.next();
		let pooled = tmp.map(|val| IPv4Addr([(val >> 24) as u8, (val >> 16) as u8, (val >> 8) as u8, val as u8]));
		return pooled.or_else( || {
			let mut viable = self.get_viable_allocs();
			viable.sort_by_key(|alloc| alloc.last_seen);

			if let Some(alloc) = viable.get(0) {
			// Remove the allocation, since we essentially just
			// freed it, and it's no longer reserved
				//self.allocations.

				return Some(alloc.assigned);
			}

			return None;
			});
	}


}
