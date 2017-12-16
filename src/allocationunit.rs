use std::boxed::Box;
use std::io::{ErrorKind, Result};
use std::net::Ipv4Addr;
use std;
use std::ops::Deref;

use allocator;
use config;
use frame::ethernet::EthernetAddr;
use lease;
use packet;

pub struct AllocationUnit {
    selector: config::Selector,
    allocator: allocator::Allocator,
    options: Box<[packet::DhcpOption]>,
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

    pub fn new(conf: config::Pool, iface: &str) -> Self {
        let pool = conf.range.get_pool(iface);
        info!("Creating allocator for {} with pool {}", iface, pool.get_name());
        let mut allocator = allocator::Allocator::new(pool, conf.allocate, conf.deallocate, conf.lease);
        let mut opts = conf.options;
        Self::default_options(&mut opts, &allocator);

        let _ = allocator.read_from(std::path::Path::new("/var/lib/dhcpd").join(iface).as_path()).map_err(|e| {
                match e.kind() {
                    ErrorKind::NotFound => {
                        info!("Couldn't find file or directory while loading allocator: {} on {}", allocator.get_name(), iface);
                    },
                    _ => {
                            error!("Couldn't read allocator {} on interface {}: {}", allocator.get_name(), iface, e);
                            println!("Couldn't read allocator {} on interface {}: {}", allocator.get_name(), iface, e);
                            std::process::exit(1);
                        },
                }
            });

        AllocationUnit {
            selector: conf.selector,
            options: opts.into_boxed_slice(),
            allocator: allocator
            }
    }

    // We can savely unwrap() here because we enforce the exiistance over default_options called by
    // new
    pub fn get_mask(&self) -> &Ipv4Addr {
        self.options.iter().find(|x| x.get_type() == 1).map(|x| match *x {
                packet::DhcpOption::SubnetMask(ref mask) => mask,
                _ => panic!("Found non SubnetMask SubnetMask"),
            }).unwrap()
    }

    pub fn save_to(&self, dir: &std::path::Path) -> Result<()> {
        self.allocator.save_to(dir)
    }

    pub fn get_name(&self) -> String { self.allocator.get_name() }

    pub fn is_suitable(&self, client: &::lease::Client<::frame::ethernet::EthernetAddr>) -> bool { self.selector.is_suitable(client) }

    pub fn get_options(&self) -> &[packet::DhcpOption] { self.options.deref() }

    pub fn get_allocation(&mut self, client: &lease::Client<EthernetAddr>, addr: Option<Ipv4Addr>) -> Option<&lease::Allocation<EthernetAddr, Ipv4Addr>> {
        self.allocator.get_allocation(client, addr)
    }

    pub fn get_renewed_lease(&mut self, client: &lease::Client<EthernetAddr>, addr: Option<Ipv4Addr>) -> Option<&lease::Lease<EthernetAddr, Ipv4Addr>> {
        self.allocator.get_renewed_lease(client, addr)
    }
}
