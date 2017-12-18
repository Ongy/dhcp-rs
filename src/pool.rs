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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GRange<P: Poolable> {
    lower: P::Internal,
    upper: P::Internal,
}

impl<P: Poolable> GRange<P> {
    fn overlapping(&self, rhs: &Self) -> bool {
        (self.lower <= rhs.upper && self.lower >= rhs.lower)
            || (self.upper >= rhs.lower && self.upper <= rhs.upper)
    }

    fn new(lower: P::Internal, upper: P::Internal) -> Option<Self> {
        if lower > upper {
            None
        } else {
            Some(GRange{lower: lower, upper: upper})
        }
    }
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

impl<P: Poolable + Clone + PartialEq> GPool<P> {
    pub fn new_multi<I>(ranges: I) -> Option<Self>
        where I: IntoIterator<Item=(P, P)> {
        let iter = ranges.into_iter().map(|(lower, upper)| GRange::new(lower.into_internal(), upper.into_internal()));
        let opt_vec: Vec<Option<GRange<P>>> = iter.collect();

        if opt_vec.iter().any(|o| o.is_none()) {
            return None;
        }

        let vec: Vec<GRange<P>> = opt_vec.into_iter().map(|o| o.unwrap()).collect();

        for i in 0 .. (vec.len() - 1) {
            for j in (i + 1) .. vec.len() {
                if vec[i].overlapping(&vec[j]) {
                    return None;
                }
            }
        }

        let b = vec.into_boxed_slice();
        let range = b[0].clone();
        Some(GPool { ranges: b, next: range.lower.clone(), current: range, range_index: 0, used: HashSet::new()})
    }

    pub fn new(lower: P, upper: P) -> Option<Self> {
        Self::new_multi(iter::once((lower, upper)))
    }
}

impl<P: Poolable> GPool<P> {

    fn size(&self) -> usize {
        let mut sum = 0;
        for range in self.ranges.deref() {
            sum += P::diff(&range.upper, &range.lower);
        }
        sum
    }

    pub fn set_used(&mut self, ip: &P) {
        self.used.insert(ip.into_internal());
    }

    #[cfg(test)]
    pub fn set_unused(&mut self, ip: &P) {
        self.used.remove(&ip.into_internal());
    }

    pub fn is_suitable(&self, ip: &P) -> bool {
        let val = ip.into_internal();
        self.ranges.iter().any(|range| range.lower <= val && range.upper >= val)
    }

    pub fn is_used(&self, ip: &P) -> bool {
        self.used.contains(&ip.into_internal())
    }

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

#[cfg(test)]
mod test {
    use super::GPool;
    use super::GRange;
    use std::net::Ipv4Addr;


    #[test]
    fn reject_invalid_range() {
        assert!(GRange::<Ipv4Addr>::new(5, 0) == None);
    }

    #[test]
    fn reject_invalid_simple() {
        assert!(GPool::new(Ipv4Addr::new(0, 0, 0, 5), Ipv4Addr::new(0, 0, 0, 1)).is_none());
    }

    #[test]
    fn simple_iter() {
        let pool = GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)).unwrap();
        let result: Vec<Ipv4Addr> = pool.collect();

        assert!(result == vec![
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 2),
            Ipv4Addr::new(0, 0, 0, 3),
            Ipv4Addr::new(0, 0, 0, 4),
            Ipv4Addr::new(0, 0, 0, 5)
        ]);
    }

    #[test]
    fn simple_size() {
        let pool = GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)).unwrap();


        assert!(pool.size() == 6);
    }

    #[test]
    fn skips_used() {
        let mut pool = GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)).unwrap();
        pool.set_used(&Ipv4Addr::new(0, 0, 0, 3));
        let result: Vec<Ipv4Addr> = pool.collect();

        assert!(result == vec![
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 2),
            Ipv4Addr::new(0, 0, 0, 4),
            Ipv4Addr::new(0, 0, 0, 5)
        ]);
    }


    #[test]
    fn returns_unused() {
        let mut pool = GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)).unwrap();
        let _ = pool.next();
        let _ = pool.next();
        let _ = pool.next();
        let _ = pool.next();
        let _ = pool.next();
        let _ = pool.next();

        pool.set_unused(&Ipv4Addr::new(0, 0, 0, 2));

        assert!(pool.next() == Some(Ipv4Addr::new(0, 0, 0, 2)));
    }

    #[test]
    fn suitable_ranges() {
        let pool = GPool::new(Ipv4Addr::new(0, 0, 0, 1), Ipv4Addr::new(0, 0, 0, 5)).unwrap();


        assert!(pool.is_suitable(&Ipv4Addr::new(0, 0, 0, 1)));
        assert!(pool.is_suitable(&Ipv4Addr::new(0, 0, 0, 5)));

        assert!(!pool.is_suitable(&Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!pool.is_suitable(&Ipv4Addr::new(0, 0, 0, 6)));
    }

    #[test]
    fn multi_iter() {
        let ranges = vec![(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)), (Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 0, 0, 5))];
        let pool = GPool::new_multi(ranges).unwrap();
        let result: Vec<Ipv4Addr> = pool.collect();

        assert!(result == vec![
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 2),
            Ipv4Addr::new(0, 0, 0, 3),
            Ipv4Addr::new(0, 0, 0, 4),
            Ipv4Addr::new(0, 0, 0, 5),

            Ipv4Addr::new(1, 0, 0, 0),
            Ipv4Addr::new(1, 0, 0, 1),
            Ipv4Addr::new(1, 0, 0, 2),
            Ipv4Addr::new(1, 0, 0, 3),
            Ipv4Addr::new(1, 0, 0, 4),
            Ipv4Addr::new(1, 0, 0, 5)
        ]);
    }

    #[test]
    fn multi_size() {
        let ranges = vec![(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)), (Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 0, 0, 5))];
        let pool = GPool::new_multi(ranges).unwrap();

        assert!(pool.size() == 12);
    }

    #[test]
    fn rejects_overlapping() {
        let ranges = vec![(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)), (Ipv4Addr::new(0, 0, 0, 3), Ipv4Addr::new(0, 0, 0, 8))];
        assert!(GPool::new_multi(ranges).is_none());
    }

    #[test]
    fn rejects_identical() {
        let ranges = vec![(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)), (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5))];
        assert!(GPool::new_multi(ranges).is_none());
    }

    #[test]
    fn simple_bounds() {
        let pool = GPool::new(Ipv4Addr::new(0, 0, 0, 1), Ipv4Addr::new(0, 0, 0, 5)).unwrap();

        assert!(pool.get_lowest() == Ipv4Addr::new(0, 0, 0, 1));
        assert!(pool.get_highest() == Ipv4Addr::new(0, 0, 0, 5));
    }

    #[test]
    fn multi_bounds() {
        let ranges = vec![(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)), (Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 0, 0, 5))];
        let pool = GPool::new_multi(ranges).unwrap();

        assert!(pool.get_lowest() == Ipv4Addr::new(0, 0, 0, 0));
        assert!(pool.get_highest() == Ipv4Addr::new(1, 0, 0, 5));
    }
}
