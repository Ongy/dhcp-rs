use std;
use ipnetwork;
use std::net::Ipv4Addr;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel;

use allocationunit;
use pnet;
use config;

pub struct Interface {
    pub allocators: Box<[allocationunit::AllocationUnit]>,
    pub name: String,
    pub my_mac: pnet::datalink::MacAddr,
    pub my_ip: Vec<Ipv4Addr>
}

impl Interface {
    pub fn save_to(&self, dir: &std::path::Path) {
        info!("Saving interface {}", &self.name);
        if !(dir.exists() && dir.is_dir()){
            warn!("Target directory for saving interface {} didn't exist", &self.name);
            return;
        }

        let my_dir = dir.join(&self.name);
        let _ = std::fs::create_dir_all(my_dir.as_path()).map_err(|e| {
                error!("Couldn't create storage directory for interface: {} in {}: {}", &self.name, dir.to_string_lossy(), e);
                ()
            });

        for alloc in self.allocators.iter() {
            let _ = alloc.save_to(my_dir.as_path()).map_err(|_| {
                error!("Encountered error while storing allocator {} on {}", alloc.get_name(), self.name);
                ()
                });
        }
    }

    /// This requires `CAP_NET_ADMIN`
    pub fn get(conf: config::Interface)
            -> (Interface, Box<pnet::datalink::DataLinkSender>, Box<pnet::datalink::DataLinkReceiver>) {
        let interfaces = datalink::interfaces();
        let interface = match interfaces.into_iter().filter(|iface: &NetworkInterface | iface.name == conf.name.as_str()).next() {
                Some(x) => x,
                None => {
                    error!("Couldn't find interface: {}", conf.name);
                    println!("Couldn't find interface: {}", conf.name);
                    std::process::exit(1);
                }
            };
        // I'm just going to asume this one, sorry :)
        let mac = interface.mac.unwrap();

        debug!("Trying to open interface: {}", &conf.name);

        let (tx, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type!"),
            Err(e) => panic!("An error occured while creating ethernet channel: {}", e)
        };
        // I love/hate this silly borrow checker and the workarounds I come up with
        let name = conf.name;
        let pool = conf.pool;

        let allocs: Vec<allocationunit::AllocationUnit> = pool.into_iter().map(|x| allocationunit::AllocationUnit::new(x, &name)).collect();
        let ip = interface.ips.into_iter().flat_map(|x| match x {
                ipnetwork::IpNetwork::V4(net) => Some(net.ip()),
                _ => None,
            }).collect();

        let ret = Interface {
            name: name,
            my_mac: mac,
            my_ip: ip,
            allocators: allocs.into_boxed_slice()
            };
        info!("Using interface {} with local mac {} and ips {:?}", &ret.name, &ret.my_mac, &ret.my_ip);

        return (ret, tx, rx);
    }

}

