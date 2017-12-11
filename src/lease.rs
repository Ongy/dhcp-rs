extern crate serde;
extern crate time;

use std;
use std::ops::Deref;

use packet;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SerializeableTime(pub time::Timespec);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Client<H> {
    pub hw_addr: H,
    pub client_identifier: Option<Box<[u8]>>,
    pub hostname: Option<String>
}

impl Deref for SerializeableTime {
    type Target = time::Timespec;
    fn deref(&self) -> &time::Timespec { &self.0 }
}

impl serde::Serialize for SerializeableTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer {
        return ((self.0).sec, (self.0).nsec).serialize(serializer);
    }
}

impl<'a> serde::Deserialize<'a> for SerializeableTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: serde::Deserializer<'a> {
        let (sec, nsec) = serde::Deserialize::deserialize(deserializer)?;
        let tspec = time::Timespec {sec: sec, nsec: nsec};
        return Ok(SerializeableTime(tspec));
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Lease<H, I> {
    pub assigned: I,
    pub client: Client<H>,
    pub lease_start: SerializeableTime,
    pub lease_duration: u32
}

fn def_false() -> bool { false }

#[derive(Debug, Serialize, Deserialize)]
pub struct Allocation<H, I> {
    pub assigned: I,
    pub client: Client<H>,
    pub last_seen: SerializeableTime,
    #[serde(default = "def_false")]
    pub forever: bool,
}

impl<H, I> Lease<H, I>
    where H: Eq,
          I: Eq {
    pub fn is_for_alloc(&self, alloc: &Allocation<H, I>) -> bool {
        let client = self.client == alloc.client;
        let addr = self.assigned == alloc.assigned;
        return client && addr;
    }
}

impl<H, I> Lease<H, I>
    where H: Clone,
          I: Clone {
    pub fn for_alloc(alloc: &Allocation<H, I>, duration: u32) -> Lease<H, I> {
        return Lease {
            assigned: alloc.assigned.clone(),
            client: alloc.client.clone(),
            lease_duration: duration,
            lease_start: SerializeableTime(time::get_time())
            };
    }
}

impl<H, I> Lease<H, I> {
    pub fn is_active(&self) -> bool {
        let passed = time::get_time() - self.lease_start.0;
        passed < time::Duration::seconds(self.lease_duration as i64)
    }
}

pub fn get_client<H>(pack: &packet::DhcpPacket<H>) -> Client<H>
    where H: Clone + std::fmt::Debug {
    let hostname = pack.options.iter().filter_map(|opt|
        match opt {
            &packet::DhcpOption::Hostname(ref name) => Some(name.clone()),
            _ => None
        }).next();
    let ci = pack.options.iter().filter_map(|opt|
        match opt {
            &packet::DhcpOption::ClientIdentifier(ref c) => Some(c.clone()),
            _ => None
        }).next();

    let ret = Client {
        hw_addr: pack.client_hwaddr.clone(),
        hostname: hostname,
        client_identifier: ci
        };

    debug!("Created client: {:?}", &ret);

    return ret;
}
