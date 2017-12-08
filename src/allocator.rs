extern crate time;
use std::iter::Iterator;
use std;
use std::io::{Error, ErrorKind, Result};

use std::io::Write;
use std::io::Read;

extern crate serde;
extern crate serde_json;

use lease;
use pool;

use frame::ethernet::EthernetAddr;
use std::net::Ipv4Addr;


// For now this is a pure ipv4 <-> ethernet allocator
pub struct Allocator {
    allocations: Vec<lease::Allocation<EthernetAddr, Ipv4Addr>>,
    leases: Vec<lease::Lease<EthernetAddr, Ipv4Addr>>,
    address_pool: pool::IPPool,
}

impl Allocator {
    /* Get the allocations we could reuse because there's no current lease
     * for them (which would lock them
     */
    fn get_viable_allocs(&self) -> Vec<&lease::Allocation<EthernetAddr, Ipv4Addr>> {
        return self.allocations.iter().filter(|alloc|
            self.leases.iter().all(|lease|
                !lease.is_for_alloc(alloc))).collect();
    }

    pub fn new(p: pool::IPPool) -> Allocator {
        Allocator { address_pool: p, leases: Vec::new(), allocations: Vec::new() }
    }

    fn find_allocation(&self, client: &lease::Client<EthernetAddr>) -> Option<usize> {
        self.allocations.iter().enumerate().find(|alloc|
&alloc.1.client == client).map(|(i, _)| i)
    }

    // We *may* be out of allocatable addresses
    fn allocation_for(&mut self, client: &lease::Client<EthernetAddr>) -> Option<&mut lease::Allocation<EthernetAddr, Ipv4Addr>> {
        trace!("Getting generated allocation");
        self.find_allocation(client).or_else(||{
            self.next_ip().map(|ip| {
                info!("Creating allocation for {:?} on ip {}", client, &ip);
                let alloc = lease::Allocation{
                    assigned: ip,
                    client: client.clone(),
                    last_seen: lease::SerializeableTime(time::get_time())
                    };
                self.allocations.push(alloc);
                self.allocations.len() - 1
            })
        }).and_then(move |i| self.allocations.get_mut(i))
    }

    fn find_lease(&self, client: &lease::Client<EthernetAddr>) -> Option<usize> {
        self.leases.iter().enumerate().find(|lease| &lease.1.client == client).map(|(i, _)| i)
    }

    pub fn get_lease_for(&mut self, client: &lease::Client<EthernetAddr>, addr: Option<Ipv4Addr>) -> Option<&lease::Lease<EthernetAddr, Ipv4Addr>> {
        //let mut found = self.find_lease(client);
        self.find_lease(client).or_else(||{
            self.get_allocation_mut(client, addr).map(|alloc|{
                alloc.last_seen = lease::SerializeableTime(time::get_time());
                lease::Lease::for_alloc(alloc, 7200)
            }).map(|l| {
                info!("Created lease for {:?}: {:?}", client, &l);
                self.leases.push(l);
                self.leases.len() - 1
            })
        }).and_then(move |i| self.leases.get(i))
    }

    fn get_requested(&mut self, client: &lease::Client<EthernetAddr>, addr: &Ipv4Addr) -> Option<&mut lease::Allocation<EthernetAddr, Ipv4Addr>> {
        trace!("Getting requested allocation");
        let ip = u32::from(*addr);
        let found = self.allocations.iter().enumerate().find(|alloc| &alloc.1.assigned == addr).map(|(i, _)| i);

        found.or_else(|| {
            if self.address_pool.is_suitable(ip) {
                info!("Creating requested allocation for {:?} on ip {}", client, addr);
                self.address_pool.set_used(ip);
                let alloc = lease::Allocation {
                    client: client.clone(),
                    assigned: addr.clone(),
                    last_seen: lease::SerializeableTime(time::get_time())
                    };
                self.allocations.push(alloc);
                Some(self.allocations.len() - 1)
            } else {
                info!("Allocator isn't suitable for requested IP");
                None
            }
        }).and_then(move |i| self.allocations.get_mut(i))
    }

    fn get_allocation_mut(&mut self, client: &lease::Client<EthernetAddr>, addr: Option<Ipv4Addr>) -> Option<&mut lease::Allocation<EthernetAddr, Ipv4Addr>> {
        match addr {
            None => self.allocation_for(client),
            Some(x) => self.get_requested(client, &x),
        }
    }

    pub fn get_allocation(&mut self, client: &lease::Client<EthernetAddr>, addr: Option<Ipv4Addr>) -> Option<&lease::Allocation<EthernetAddr, Ipv4Addr>> {
        // Simply cast the mut away
        trace!("Trying to get an allocation");
        self.get_allocation_mut(client, addr).map(|x| &*x)
    }

    fn serialize_leases(&self) -> String {
        serde_json::to_string(&self.leases).unwrap()
    }

    fn serialize_allocs(&self) -> String {
        serde_json::to_string(&self.allocations).unwrap()
    }

    fn ensure_alloc(&mut self, lease: &lease::Lease<EthernetAddr, Ipv4Addr>) -> Result<()> {
        match self.get_allocation(&lease.client, Some(lease.assigned)) {
            Some(_) => Ok(()),
            None => {
                error!("Couldn't create allocation for lease: {:?}", lease);
                Err(Error::new(ErrorKind::InvalidInput, format!("Couldn't create allocation for lease: {:?}", lease)))
            },
        }
    }

    fn deserialize_leases(&mut self, leases: &str) -> Result<()> {
        let leases = serde_json::from_str(leases)?;

        for lease in &leases {
            self.ensure_alloc(lease)?;
        }

        self.leases = leases;

        Ok(())
    }

    fn deserialize_allocs(&mut self, allocs: &str) -> Result<()> {
        self.allocations = serde_json::from_str(allocs)?;

        for alloc in &self.allocations {
            self.address_pool.set_used(alloc.assigned.into());
        }

        Ok(())
    }

    fn next_ip(&mut self) -> Option<Ipv4Addr> {
        let pooled = self.address_pool.next();
        return pooled.or_else( || {
            let mut viable = self.get_viable_allocs();
            viable.sort_by_key(|alloc| alloc.last_seen);

            if let Some(alloc) = viable.get(0) {
            // Remove the allocation, since we essentially just
            // freed it, and it's no longer reserved
                //self.allocations.

                return Some(alloc.assigned);
            }

            return None;
            });
    }

    pub fn get_name(&self) -> String {
        self.address_pool.get_name()
    }

    fn read_leases(&mut self, my_dir: &std::path::Path) -> Result<()> {
        let lease_file = my_dir.join("leases.json");
        let mut lease = std::fs::File::open(lease_file)?;
        let mut lease_str = String::new();
        lease.read_to_string(&mut lease_str)?;
        self.deserialize_leases(lease_str.as_str())?;
        Ok(())
    }

    fn read_allocs(&mut self, my_dir: &std::path::Path) -> Result<()> {
        let alloc_file = my_dir.join("allocations.json");
        let mut alloc = std::fs::File::open(alloc_file)?;
        let mut alloc_str = String::new();
        alloc.read_to_string(&mut alloc_str)?;
        self.deserialize_allocs(alloc_str.as_str())?;
        Ok(())
    }

    pub fn read_from(&mut self, dir: &std::path::Path) -> Result<()> {
        let my_dir = dir.join(self.get_name());
        if !(my_dir.exists() && my_dir.is_dir()){
            return Err(Error::new(ErrorKind::NotFound, format!("Couldn't find directory {} while trying to read allocator from file", my_dir.to_string_lossy())));
        }

        self.read_allocs(my_dir.as_path()).or_else(|e| if e.kind() == ErrorKind::NotFound { Ok(()) } else { Err(e) })?;
        self.read_leases(my_dir.as_path()).or_else(|e| if e.kind() == ErrorKind::NotFound { Ok(()) } else { Err(e) })?;

        Ok(())
    }

    fn write_leases(&self, my_dir: &std::path::Path) -> Result<()> {
        let lease_file = my_dir.join("leases.json");
        let mut leases = std::fs::File::create(lease_file)?;
        leases.write_all(self.serialize_leases().as_bytes())?;

        Ok(())
    }

    fn write_allocs(&self, my_dir: &std::path::Path) -> Result<()> {
        let alloc_file = my_dir.join("allocations.json");
        let mut allocs = std::fs::File::create(alloc_file)?;
        allocs.write_all(self.serialize_allocs().as_bytes())?;

        Ok(())
    }

    pub fn save_to(&self, dir: &std::path::Path) -> Result<()> {
        let mut ret = Ok(());
        if !(dir.exists() && dir.is_dir()){
            return Err(Error::new(ErrorKind::NotFound, format!("Couldn't find directory {} while trying to write allocator to file", dir.to_string_lossy())));
        }

        let my_dir = dir.join(self.get_name());
        std::fs::create_dir_all(my_dir.as_path())?;

        let _ = self.write_leases(my_dir.as_path()).map_err(|e| {
                error!("Failed to write leases to file: {}", e);
                ret = Err(e);
                ()
            });

        let _ = self.write_allocs(my_dir.as_path()).map_err(|e| {
                error!("Failed to write allocations to file: {}", e);
                ret = Err(e);
                ()
            });


        return ret;
    }

    pub fn get_bounds(&self) -> (Ipv4Addr, Ipv4Addr) {
        (self.address_pool.get_lowest(), self.address_pool.get_highest())
    }
}
