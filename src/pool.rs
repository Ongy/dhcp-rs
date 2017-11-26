use std::boxed::Box;
use std::collections::HashSet;
use std::iter::Iterator;

use std::ops::Deref;

#[derive(Debug, Clone, Copy)]
struct IPRange {
	lower: u32,
	upper: u32
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
	type Item=u32;

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
				return Some(current);
			}

		}
	}
}

impl IPPool {
	pub fn new(lower: u32, upper: u32) -> Self {
		let range = IPRange{lower: lower, upper: upper};
		let b = vec![range].into_boxed_slice();
		return IPPool { ranges: b, next: lower, current: range,
range_index: 0, used: HashSet::new()};
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
}
