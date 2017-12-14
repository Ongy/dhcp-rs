extern crate rs_config;

mod ippool;
use self::ippool::IPPool;

use rs_config::ConfigAble;
use std::net::Ipv4Addr;
use ::frame::ethernet::EthernetAddr;

use log::LogLevel;

#[derive(Debug, ConfigAble)]
pub struct IPNet(pub Ipv4Addr, pub u8);

#[derive(Debug, ConfigAble)]
#[ConfigAttrs(default="Selector::All")]
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
    pub options: Vec<::packet::DhcpOption>,

    pub allocate: Option<String>,
    pub lease: Option<String>,
    pub deallocate: Option<String>,
}

#[derive(Debug, ConfigAble)]
pub struct Interface {
    pub name: String,
    pub pool: Vec<Pool>
}

#[derive(Debug, ConfigAble)]
pub struct Config {
    pub log_level: LogLevel,
    #[ConfigAttrs(default="String::from(\"/var/lib/dhcpd\")")]
    pub cache_dir: String,
    pub interfaces: Vec<Interface>
}
