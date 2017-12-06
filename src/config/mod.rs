extern crate rs_config;

use rs_config::ConfigAble;
use std::net::Ipv4Addr;
use ::frame::ethernet::EthernetAddr;

use ::pool;

#[derive(Debug, ConfigAble)]
pub struct IPRange {
    pub lower: Ipv4Addr,
    pub upper: Ipv4Addr
}

#[derive(Debug, ConfigAble)]
pub struct IPNet(pub Ipv4Addr, pub u8);

#[derive(Debug, ConfigAble)]
pub enum IPPool {
    Guess,
    Range(IPRange),
    Ranges(Box<[IPRange]>)
}

impl IPPool {
    pub fn get_pool(self, _: &String) -> pool::IPPool {
        match self {
            IPPool::Range(range) => pool::IPPool::new(range.lower, range.upper),
            IPPool::Ranges(ranges) => pool::IPPool::new_multi(ranges.into_iter().map(|r| (r.lower, r.upper))),
            _ => panic!("Didn't implement that pool method yet"),
        }
    }
}

#[derive(Debug, ConfigAble)]
pub enum Selector {
    All,
    Macs(Box<[EthernetAddr]>),
    Hostnames(Box<[String]>),
    Either(Box<[Selector]>)
}

impl Selector {
    pub fn is_suitable(&self, client: &::lease::Client<::frame::ethernet::EthernetAddr>) -> bool {
        match *self {
            Selector::All => true,
            Selector::Macs(ref b) => b.iter().any(|x| x == &client.hw_addr),
            Selector::Hostnames(ref b) => match client.hostname {
                // Why is this so hard to do with .map()? :(
                    None => false,
                    Some(ref name) => b.iter().any(|x| name == x),
                }
            Selector::Either(ref b) => b.iter().any(|s| s.is_suitable(client)),
        }
    }
}

#[derive(Debug, ConfigAble)]
pub struct Pool {
    pub selector: Selector,
    pub range: IPPool,
    pub options: Vec<::packet::DhcpOption>
}

#[derive(Debug, ConfigAble)]
pub struct Interface {
    pub name: String,
    pub pool: Vec<Pool>
}
