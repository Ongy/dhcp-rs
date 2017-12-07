extern crate itertools;
use self::itertools::Itertools;

use std::boxed::Box;
use std::collections::HashSet;
use std::iter;
use std::iter::Iterator;

use std::ops::Deref;

use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy)]
struct IPRange {
	lower: u32,
	upper: u32
}

impl IPRange {
    fn get_name(&self) -> String {
        format!("{}-{}", Ipv4Addr::from(self.lower), Ipv4Addr::from(self.upper))
    }
}

#[derive(Debug)]
pub struct IPPool {
	ranges: Box<[IPRange]>,
	next: u32,
	current: IPRange,
	range_index: usize,
	used: HashSet<u32>,
}

impl Iterator for IPPool {
	type Item=Ipv4Addr;

	fn next(&mut self) -> Option<Self::Item> {
		let mut current = self.next;

		if self.used.len() >= self.size() {
			return None;
		}

		loop {
			// Go into the next ip range of the pool
			if current > self.current.upper {
				self.range_index = (self.range_index + 1) % self.ranges.len();
				self.current = self.ranges[self.range_index];
				current = self.current.lower;
			}

			// If it's already used, skip it.
			if self.used.contains(&current) {
				current = current + 1;
				continue;
			}

			// If it's valid for the pool return it
			if current <= self.current.upper {
				self.next = current + 1;
				self.used.insert(current);
				return Some(Ipv4Addr::from(current));
			}

		}
	}
}

impl IPPool {
    pub fn new_multi<I>(ranges: I) -> Self
        where I: Iterator<Item=(Ipv4Addr, Ipv4Addr)> {
		let iter = ranges.map(|(lower, upper)| IPRange{lower: lower.into(), upper: upper.into()});
        let vec: Vec<IPRange> = iter.collect();
		let b = vec.into_boxed_slice();
        let range = b.iter().next().unwrap().clone();
		return IPPool { ranges: b, next: range.lower.into(), current: range, range_index: 0, used: HashSet::new()};
    }

	pub fn new(lower: Ipv4Addr, upper: Ipv4Addr) -> Self {
        return Self::new_multi(iter::once((lower, upper)));

		//let range = IPRange{lower: lower.into(), upper: upper.into()};
		//let b = vec![range].into_boxed_slice();
		//return IPPool { ranges: b, next: lower.into(), current: range, range_index: 0, used: HashSet::new()};
	}

	fn size(&self) -> usize {
		let mut sum = 0;
		for range in self.ranges.deref() {
			sum += range.upper as usize - range.lower as usize + 1;
		}
		return sum;
	}

	pub fn set_used(&mut self, ip: u32) {
		self.used.insert(ip);
	}

	//pub fn set_unused(&mut self, ip: u32) {
	//	self.used.remove(&ip);
	//}

	pub fn is_suitable(&self, ip: u32) -> bool {
		return self.ranges.iter().any(|range| range.lower <= ip && range.upper >= ip);
	}

    pub fn get_name(&self) -> String {
        self.ranges.iter().map(|r| r.get_name()).join("_")
    }
}
