use std::boxed::Box;
use std::io::{ErrorKind, Result};
use std::net::Ipv4Addr;
use std;
use std::ops::Deref;
use std::path::Path;
use std::fmt::Display;

use allocator;
use pool;
use config;
use frame::ethernet::EthernetAddr;
use lease;
use packet;

pub struct AllocationUnit {
    selector: config::Selector,
    allocator: allocator::Allocator,
    options: Box<[packet::DhcpOption]>,
    lease_time: u32
}


impl AllocationUnit {

    //TODO: Pass debug info into here for logs?
    fn default_options(opts: &mut Vec<packet::DhcpOption>,
                       alloc: &allocator::Allocator) {
        if !opts.iter().any(|opt| opt.get_type() == 51) {
            info!("Defaulting lease time");
            opts.push(packet::DhcpOption::LeaseTime(86_400));
        }

        if !opts.iter().any(|opt| opt.get_type() == 1) {
            warn!("Defaulting SubnetMask");

            let (min, max) = alloc.get_bounds();
            let min_u32: u32 = min.into();
            let max_u32: u32 = max.into();

            /* Get the number of bits in the netmask */
            let prefix = (min_u32 ^ max_u32).leading_zeros();
            let mask = (!0u32) << (32 - prefix);
            let val = Ipv4Addr::from(mask);

            opts.push(packet::DhcpOption::SubnetMask(val));
        }
    }

    fn new(pool: pool::GPool<Ipv4Addr>,
           sel: config::Selector,
           mut opts: Vec<packet::DhcpOption>,
           lease: Option<String>,
           alloc: Option<String>,
           dealloc: Option<String>)
           -> Self {
        let allocator = allocator::Allocator::new(pool, alloc, dealloc, lease);
        Self::default_options(&mut opts, &allocator);

        let options = opts.into_boxed_slice();

        AllocationUnit {
            lease_time: Self::get_lease_time(options.iter()),
            selector: sel,
            options: options,
            allocator: allocator,
            }
    }

    pub fn from_conf<D: AsRef<Path> + Display>(conf: config::Pool, iface: &str, dir: D) -> Self {
        let pool = conf.range.get_pool(iface).unwrap();
        info!("Creating allocator for {} with pool {}", iface, pool.get_name());
        let mut ret = Self::new(pool, conf.selector, conf.options, conf.lease, conf.allocate, conf.deallocate);

        let _ = ret.allocator.read_from(dir.as_ref()).map_err(|e| {
                match e.kind() {
                    ErrorKind::NotFound => {
                        info!("Couldn't find file or directory while loading allocator: {} on {}", ret.get_name(), iface);
                    },
                    _ => {
                            error!("Couldn't read allocator {} on interface {}: {}", ret.get_name(), iface, e);
                            println!("Couldn't read allocator {} on interface {}: {}", ret.get_name(), iface, e);
                            std::process::exit(1);
                        },
                }
            });

        ret
    }

    // We can savely unwrap() here because we enforce the exiistance over default_options called by
    // new
    pub fn get_mask(&self) -> &Ipv4Addr {
        self.options.iter().find(|x| x.get_type() == 1).map(|x| match *x {
                packet::DhcpOption::SubnetMask(ref mask) => mask,
                _ => panic!("Found non SubnetMask SubnetMask"),
            }).unwrap()
    }

    fn get_lease_time<'a, I: IntoIterator<Item=&'a packet::DhcpOption>>(it: I) -> u32 {
        it.into_iter().find(|x| x.get_type() == 51).map(|x| match *x {
                packet::DhcpOption::LeaseTime(time) => time,
                _ => panic!("Found non SubnetMask SubnetMask"),
            }).unwrap()
    }

    pub fn save_to(&self, dir: &std::path::Path) -> Result<()> {
        self.allocator.save_to(dir)
    }

    pub fn get_name(&self) -> String { self.allocator.get_name() }

    pub fn is_suitable(&self, client: &lease::Client<::frame::ethernet::EthernetAddr>) -> bool { self.selector.is_suitable(client) }

    pub fn get_options(&self) -> &[packet::DhcpOption] { self.options.deref() }

    pub fn get_allocation(&mut self, client: &lease::Client<EthernetAddr>, addr: Option<Ipv4Addr>) -> Option<&lease::Allocation<EthernetAddr, Ipv4Addr>> {
        self.allocator.get_allocation(client, addr)
    }

    pub fn get_renewed_lease(&mut self, client: &lease::Client<EthernetAddr>, addr: Option<Ipv4Addr>) -> Option<&lease::Lease<EthernetAddr, Ipv4Addr>> {
        self.allocator.get_renewed_lease(client, addr, self.lease_time)
    }
}

#[cfg(test)]
mod test {
    use super::AllocationUnit;
    use config::Selector;
    use pool::GPool;
    use std::net::Ipv4Addr;

    #[test]
    fn defaults_mask() {
        let pool = GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 254)).unwrap();
        let au = AllocationUnit::new(pool, Selector::All, vec![], None, None, None);
        assert!(au.get_mask() == &Ipv4Addr::new(255, 255, 255, 0));

        let pool2 = GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 255, 0, 0)).unwrap();
        let au2 = AllocationUnit::new(pool2, Selector::All, vec![], None, None, None);
        assert!(au2.get_mask() == &Ipv4Addr::new(255, 0, 0, 0));

        let pool3 = GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 127, 0)).unwrap();
        let au3 = AllocationUnit::new(pool3, Selector::All, vec![], None, None, None);
        assert!(au3.get_mask() == &Ipv4Addr::new(255, 255, 128, 0));
    }
}
