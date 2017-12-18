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
    address_pool: pool::GPool<Ipv4Addr>,

    deallocate_hook: Option<String>,
    allocate_hook: Option<String>,
    lease_hook: Option<String>
}

impl Allocator {
    fn make_alloc(&self,
                  assigned: Ipv4Addr,
                  client: lease::Client<EthernetAddr>)
                  -> lease::Allocation<EthernetAddr, Ipv4Addr> {
        match self.allocate_hook {
            None => {},
            Some(ref path) => {
                let hostname = client.hostname
                                .as_ref()
                                .map(|s| s.as_ref())
                                .unwrap_or("");
                let ip = format!("{}", &assigned);
                let hwaddr = format!("{}", &client.hw_addr);
                let cmd = std::process::Command::new(path)
                            .arg(ip)
                            .arg(hwaddr)
                            .arg(hostname)
                            .status();

                if !(cmd.is_ok() && cmd.as_ref().unwrap().success()) {
                    warn!("Failed to execute allocation notify command: {:?}", cmd);
                }
            }
        }



        lease::Allocation{
            assigned: assigned,
            client: client,
            last_seen: lease::SerializeableTime(time::get_time()),
            forever: false,
            }
    }

    fn del_alloc(&self,
                 alloc: lease::Allocation<EthernetAddr, Ipv4Addr>) {
        if let Some(ref path) = self.deallocate_hook {
            let client = alloc.client;
            let hostname = client.hostname
                            .as_ref()
                            .map(|s| s.as_ref())
                            .unwrap_or("");
            let ip = format!("{}", &alloc.assigned);
            let hwaddr = format!("{}", &client.hw_addr);
            let cmd = std::process::Command::new(path)
                        .arg(ip)
                        .arg(hwaddr)
                        .arg(hostname)
                        .status();

            if !(cmd.is_ok() && cmd.as_ref().unwrap().success()) {
                warn!("Failed to execute allocation notify command: {:?}", cmd);
            }
        }
    }

    fn renew_lease(lease_hook: &Option<String>,
                  lease: &mut lease::Lease<EthernetAddr, Ipv4Addr>) {
        match *lease_hook {
            None => {},
            Some(ref path) => {
                let client = &lease.client;
                let hostname = client.hostname
                                .as_ref()
                                .map(|s| s.as_ref())
                                .unwrap_or("");
                let ip = format!("{}", &lease.assigned);
                let hwaddr = format!("{}", &client.hw_addr);
                let cmd = std::process::Command::new(path)
                            .arg(ip)
                            .arg(hwaddr)
                            .arg(hostname)
                            .status();

                if !(cmd.is_ok() && cmd.as_ref().unwrap().success()) {
                    warn!("Failed to execute lease notify command: {:?}", cmd);
                }
            }
        }

        lease.lease_start = lease::SerializeableTime(time::get_time());
    }

    /* Get the allocations we could reuse because there's no current lease
     * for them (which would lock them
     */
    fn get_viable_allocs(&self) -> Vec<&lease::Allocation<EthernetAddr, Ipv4Addr>> {
        self.allocations.iter().filter(|alloc| !alloc.forever).filter(|alloc|
            self.leases.iter().filter(|l| l.is_active()).all(|lease|
                !lease.is_for_alloc(alloc))).collect()
    }

    pub fn new(p: pool::GPool<Ipv4Addr>, allocate: Option<String>, deallocate: Option<String>, lease: Option<String>) -> Allocator {
        Allocator { address_pool: p, leases: Vec::new(), allocations: Vec::new(), allocate_hook: allocate, lease_hook: lease, deallocate_hook: deallocate}
    }

    fn find_allocation(&self, client: &lease::Client<EthernetAddr>) -> Option<usize> {
        self.allocations
            .iter().position(|alloc| alloc.client == *client)
            .or_else(|| self.allocations.iter().position(|alloc| client.client_identifier.is_some() && alloc.client.client_identifier == client.client_identifier))
            .or_else(|| self.allocations.iter().position(|alloc| alloc.client.hw_addr == client.hw_addr))
            .or_else(|| self.allocations.iter().position(|alloc| client.hostname.is_some() && alloc.client.hostname == client.hostname))
    }

    // We *may* be out of allocatable addresses
    fn allocation_for(&mut self, client: &lease::Client<EthernetAddr>) -> Option<&mut lease::Allocation<EthernetAddr, Ipv4Addr>> {
        trace!("Getting generated allocation");
        self.find_allocation(client).or_else(||{
            self.next_ip().map(|ip| {
                info!("Creating allocation for {:?} on ip {}", client, &ip);
                let alloc = self.make_alloc(ip, client.clone());
                self.allocations.push(alloc);
                self.allocations.len() - 1
            })
        }).and_then(move |i| self.allocations.get_mut(i))
    }

    /// Find the *index* of a lease in our store
    /// This is a bit silly, but required because we can't return a reference to it, without
    /// borrowing self, so this works around it
    fn find_lease(&self, client: &lease::Client<EthernetAddr>) -> Option<usize> {
        self.leases
            .iter().position(|alloc| alloc.client == *client)
            .or_else(|| self.leases.iter().position(|lease| client.client_identifier.is_some() && lease.client.client_identifier == client.client_identifier))
            .or_else(|| self.leases.iter().position(|lease| lease.client.hw_addr == client.hw_addr))
            .or_else(|| self.leases.iter().position(|lease| client.hostname.is_some() && lease.client.hostname == client.hostname))
    }

    pub fn get_renewed_lease(&mut self, client: &lease::Client<EthernetAddr>, addr: Option<Ipv4Addr>) -> Option<&lease::Lease<EthernetAddr, Ipv4Addr>> {
        let hook = self.lease_hook.clone();
        if let Some(a) = self.get_allocation_mut(client, addr) {
            a.last_seen = lease::SerializeableTime(time::get_time());
        }

        self.get_lease_mut(client, addr).map(|l| { Self::renew_lease(&hook, l); &*l })
    }

    fn get_lease_mut(&mut self,
                     client: &lease::Client<EthernetAddr>, addr:
                     Option<Ipv4Addr>)
                     -> Option<&mut lease::Lease<EthernetAddr, Ipv4Addr>> {
        self.find_lease(client).or_else(||{
            self.get_allocation_mut(client, addr)
                .map(|alloc| lease::Lease::for_alloc(alloc, 7200))
                .map(|l| {
                info!("Created lease for {:?}: {:?}", client, &l);
                self.leases.push(l);
                self.leases.len() - 1
            })
        }).and_then(move |i| self.leases.get_mut(i))
    }

    fn get_requested(&mut self,
                     client: &lease::Client<EthernetAddr>,
                     addr: &Ipv4Addr)
                     -> Option<&mut lease::Allocation<EthernetAddr, Ipv4Addr>> {
        trace!("Getting requested allocation");
        let found = self.allocations
            .iter()
            .position(|alloc| alloc.assigned == *addr
                          && client.overlapping(&alloc.client));

        found.or_else(|| {
            if self.address_pool.is_suitable(addr)
                    && !self.address_pool.is_used(addr) {
                info!("Creating requested allocation for {:?} on ip {}", client, addr);
                self.address_pool.set_used(addr);
                let alloc = self.make_alloc(*addr, client.clone());
                self.allocations.push(alloc);
                Some(self.allocations.len() - 1)
            } else {
                info!("Allocator isn't suitable for requested IP or requested IP is taken");
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
        let leases: Vec<lease::Lease<EthernetAddr, Ipv4Addr>> = serde_json::from_str(leases)?;

        for lease in &leases {
            self.ensure_alloc(lease)?;
        }

        self.leases = leases.into_iter().filter(|l| l.is_active()).collect();

        Ok(())
    }

    fn deserialize_allocs(&mut self, allocs: &str) -> Result<()> {
        self.allocations = serde_json::from_str(allocs)?;

        for alloc in &self.allocations {
            self.address_pool.set_used(&alloc.assigned);
        }

        Ok(())
    }

    fn provide_ip(&mut self) -> Option<(Ipv4Addr, bool)> {
        let pooled = self.address_pool.next().map(|i| (i, false));
        pooled.or_else( || {

            let mut viable = self.get_viable_allocs();
            viable.sort_by_key(|alloc| alloc.last_seen);

            if let Some(alloc) = viable.get(0) {
                return Some((alloc.assigned, true));
            }

            None
            })
    }

    fn next_ip(&mut self) -> Option<(Ipv4Addr)> {
        if let Some((i, freed)) = self.provide_ip() {
            if !freed {
                return Some(i);
            }

            // Ok, we freed the old allocation. We should remove it
            // This is actually guaranteed, so we can unwrap!
            let index = self.allocations.iter().position(|alloc| alloc.assigned == i).unwrap();
            let alloc = self.allocations.swap_remove(index);
            self.del_alloc(alloc);

            Some(i)
        } else {
            None
        }
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


        ret
    }

    pub fn get_bounds(&self) -> (Ipv4Addr, Ipv4Addr) {
        (self.address_pool.get_lowest(), self.address_pool.get_highest())
    }
}

#[cfg(test)]
mod test {
    use super::Allocator;
    use pool::GPool;
    use std::net::Ipv4Addr;
    use frame::ethernet::EthernetAddr;
    use lease;

    #[test]
    fn gets_first() {
        let mut alloc = Allocator::new(GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)).unwrap(), None, None, None);
        let client = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 0])};

        assert!(alloc.get_allocation(&client, None).map(|a| a.assigned == Ipv4Addr::new(0, 0, 0, 0)).unwrap_or(false));
    }

    #[test]
    fn gets_next () {
        let mut alloc = Allocator::new(GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)).unwrap(), None, None, None);
        let client = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 0])};
        let client2 = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 1])};

        let _ = alloc.get_allocation(&client, None);
        assert!(alloc.get_allocation(&client2, None).map(|a| a.assigned == Ipv4Addr::new(0, 0, 0, 1)).unwrap_or(false));
    }

    #[test]
    fn gets_same () {
        let mut alloc = Allocator::new(GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)).unwrap(), None, None, None);
        let client = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 0])};

        let _ = alloc.get_allocation(&client, None);
        assert!(alloc.get_allocation(&client, None).map(|a| a.assigned == Ipv4Addr::new(0, 0, 0, 0)).unwrap_or(false));
    }

    #[test]
    fn gets_requested() {
        let mut alloc = Allocator::new(GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)).unwrap(), None, None, None);
        let client = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 0])};

        assert!(alloc.get_allocation(&client, Some(Ipv4Addr::new(0, 0, 0, 2))).map(|a| a.assigned == Ipv4Addr::new(0, 0, 0, 2)).unwrap_or(false));
    }

    #[test]
    fn gets_requested_again() {
        let mut alloc = Allocator::new(GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)).unwrap(), None, None, None);
        let client = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 0])};

        let _ = alloc.get_allocation(&client, Some(Ipv4Addr::new(0, 0, 0, 2)));
        assert!(alloc.get_allocation(&client, None).map(|a| a.assigned == Ipv4Addr::new(0, 0, 0, 2)).unwrap_or(false));
    }

    #[test]
    fn denies_requested() {
        let mut alloc = Allocator::new(GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)).unwrap(), None, None, None);
        let client = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 0])};
        let client2 = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 1])};

        let _ = alloc.get_allocation(&client, None);
        assert!(alloc.get_allocation(&client2, Some(Ipv4Addr::new(0, 0, 0, 0))).is_none());
    }

    #[test]
    fn denies_unsuitable() {
        let mut alloc = Allocator::new(GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 5)).unwrap(), None, None, None);
        let client = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 0])};

        assert!(alloc.get_allocation(&client, Some(Ipv4Addr::new(0, 0, 0, 6))).is_none());
    }

    #[test]
    fn frees_oldest() {
        let mut alloc = Allocator::new(GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 2)).unwrap(), None, None, None);
        let client = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 0])};
        let client2 = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 1])};
        let client3 = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 2])};
        let client4 = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 3])};

        let _ = alloc.get_allocation(&client, None);
        let _ = alloc.get_allocation(&client2, None);
        let _ = alloc.get_allocation(&client3, None);

        assert!(alloc.get_allocation(&client4, None).map(|a| a.assigned == Ipv4Addr::new(0, 0, 0, 0)).unwrap_or(false));
    }

    #[test]
    fn frees_non_leased() {
        let mut alloc = Allocator::new(GPool::new(Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 2)).unwrap(), None, None, None);
        let client = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 0])};
        let client2 = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 1])};
        let client3 = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 2])};
        let client4 = lease::Client{client_identifier: None, hostname: None, hw_addr: EthernetAddr([0, 0, 0, 0, 0, 3])};

        let _ = alloc.get_renewed_lease(&client, None);
        let _ = alloc.get_allocation(&client2, None);
        let _ = alloc.get_allocation(&client3, None);

        assert!(alloc.get_allocation(&client4, None).map(|a| a.assigned == Ipv4Addr::new(0, 0, 0, 1)).unwrap_or(false));
    }
}
