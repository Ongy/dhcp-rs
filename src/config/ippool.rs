extern crate rs_config;

use pnet::datalink::{self, NetworkInterface};
use rs_config::ConfigAble;
use std::net::Ipv4Addr;
use std;
use ipnetwork;

use ::pool;

#[derive(Debug, ConfigAble)]
pub struct IPRange {
    pub lower: Ipv4Addr,
    pub upper: Ipv4Addr
}

#[derive(Debug, ConfigAble)]
#[ConfigAttrs(default="IPPool::Guess")]
pub enum IPPool {
    Guess,
    Range(IPRange),
    Ranges(Box<[IPRange]>)
}

impl IPPool {
    pub fn get_pool(self, name: &str) -> pool::GPool<Ipv4Addr> {
        match self {
            IPPool::Range(range) => pool::GPool::new(range.lower, range.upper),
            IPPool::Ranges(ranges) => pool::GPool::new_multi(ranges.into_iter().map(|r| (r.lower, r.upper))),
            IPPool::Guess => {
                info!("Guessing range for interface: {}", name);
                let interfaces = datalink::interfaces();
                let interface = match interfaces
                            .into_iter()
                            .find(|iface: &NetworkInterface |
                                        iface.name == name)
                            {
                        Some(x) => x,
                        None => {
                            error!("Couldn't find interface: {}", name);
                            std::process::exit(1)
                        }
                    };
                let ip: Vec<ipnetwork::Ipv4Network> = interface.ips.into_iter().flat_map(|x| match x {
                        ipnetwork::IpNetwork::V4(net) => Some(net),
                        _ => None,
                    }).collect();

                if ip.len() != 1 {
                    error!("Cannot guess IPPool to use when there's more than one address on interface: {}", name);
                    std::process::exit(1);

                }

                // this is save here, we got exactly one!
                let net = ip.into_iter().next().unwrap();

                let lower = net.network();
                let upper = net.broadcast();
                let own = net.ip();

                info!("Using range: {}-{}. Reserving {} for my own", lower, upper, own);

                let mut pool = pool::GPool::new(lower, upper);
                pool.set_used(&lower);
                pool.set_used(&upper);
                pool.set_used(&own);

                pool
            }
        }
    }
}

