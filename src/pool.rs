extern crate itertools;
use self::itertools::Itertools;

use std;
use std::boxed::Box;
use std::collections::HashSet;
use std::iter;
use std::iter::Iterator;

use std::ops::Deref;

use std::net::Ipv4Addr;

pub trait Poolable {
    type Internal: std::cmp::Ord + std::hash::Hash + Clone;
    fn into_internal(&self) -> Self::Internal;
    fn from_internal(&Self::Internal) -> Self;
    fn advance(Self::Internal) -> Self::Internal;
    fn diff(&Self::Internal, &Self::Internal) -> usize;
}

impl Poolable for Ipv4Addr {
    type Internal = u32;

    fn into_internal(&self) -> u32 { u32::from(*self) }
    fn from_internal(arg: &u32) -> Self { Ipv4Addr::from(*arg) }
    fn advance(arg: u32) -> u32 { arg + 1 }
    fn diff(arg1: &u32, arg2: &u32) -> usize { *arg1 as usize - *arg2 as usize + 1 }
}

#[derive(Debug, Clone, Copy)]
struct GRange<P: Poolable> {
    lower: P::Internal,
    upper: P::Internal,
}

impl<P: std::fmt::Display + Poolable> GRange<P> {
    fn get_name(&self) -> String {
        format!("{}-{}", P::from_internal(&self.lower), P::from_internal(&self.upper))
    }
}

#[derive(Debug)]
pub struct GPool<P: Poolable> {
    ranges: Box<[GRange<P>]>,
    next: P::Internal,
    current: GRange<P>,
    range_index: usize,
    used: HashSet<P::Internal>,
}

impl<P: Poolable + Clone> Iterator for GPool<P> {
    type Item=P;

    fn next(&mut self) -> Option<Self::Item> {
        let mut current = self.next.clone();

        if self.used.len() >= self.size() {
            return None;
        }

        loop {
            // Go into the next ip range of the pool
            if current > self.current.upper {
                self.range_index = (self.range_index + 1) % self.ranges.len();
                self.current = self.ranges[self.range_index].clone();
                current = self.current.lower.clone();
            }

            // If it's already used, skip it.
            if self.used.contains(&current) {
                current = P::advance(current);
                continue;
            }

            // If it's valid for the pool return it
            if current <= self.current.upper {
                self.next = P::advance(current.clone());
                self.used.insert(current.clone());
                return Some(P::from_internal(&current));
            }

        }
    }
}

impl<P: Poolable + Clone> GPool<P> {
    pub fn new_multi<I>(ranges: I) -> Self
        where I: Iterator<Item=(P, P)> {
        let iter = ranges.map(|(lower, upper)| GRange{lower: lower.into_internal(), upper: upper.into_internal()});
        let vec: Vec<GRange<P>> = iter.collect();
        let b = vec.into_boxed_slice();
        let range = b.iter().next().unwrap().clone();
        return GPool { ranges: b, next: range.lower.clone(), current: range, range_index: 0, used: HashSet::new()};
    }

    pub fn new(lower: P, upper: P) -> Self {
        return Self::new_multi(iter::once((lower, upper)));
    }
}

impl<P: Poolable> GPool<P> {

    fn size(&self) -> usize {
        let mut sum = 0;
        for range in self.ranges.deref() {
            sum += P::diff(&range.upper, &range.lower);
        }
        return sum;
    }

    pub fn set_used(&mut self, ip: P) {
        self.used.insert(ip.into_internal());
    }

    //pub fn set_unused(&mut self, ip: u32) {
    //    self.used.remove(&ip);
    //}

    pub fn is_suitable(&self, ip: P) -> bool {
        let val = ip.into_internal();
        return self.ranges.iter().any(|range| range.lower <= val && range.upper >= val);
    }

//    pub fn is_used(&self, ip: u32) -> bool {
//        return self.used.contains(&ip);
//    }

    pub fn get_lowest(&self) -> P {
        P::from_internal(self.ranges.iter().map(|r| &r.lower).min().unwrap())
    }

    pub fn get_highest(&self) -> P {
        P::from_internal(self.ranges.iter().map(|r| &r.upper).max().unwrap())
    }
}

impl<P: Poolable + std::fmt::Display> GPool<P> {
    pub fn get_name(&self) -> String {
        self.ranges.iter().map(|r| r.get_name()).join("_")
    }
}
