#[cfg(test)]
#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate rs_config_derive;
extern crate rs_config;

extern crate clap;

extern crate syslog;
extern crate pnet;
extern crate time;
extern crate ipnetwork;
extern crate privdrop;

mod frame;
mod lease;
mod packet;
mod pool;
mod serialize;
mod allocator;
mod config;
mod allocationunit;
mod interface;
mod handler;

use clap::{Arg, App};

fn run_server(path: &str) {
    let conf: config::Config = rs_config::read_or_exit(path);

    syslog::init(syslog::Facility::LOG_DAEMON,
                 conf.log_level.to_log_level_filter(),
                 Some("dhcpd")).unwrap();
    info!("Starting up dhcp server");

    trace!("Changing to / cwd");
    match std::env::set_current_dir("/") {
        Ok(()) => {},
        Err(e) => {
            error!("Failed to change dir to /: {}", e);
        }
    }

    let threads: Vec<std::thread::JoinHandle<()>> =
            conf.interfaces.into_iter()
            .map(|i| handler::handle_interface(i))
            .collect();

    match privdrop::PrivDrop::default().user("dhcp").apply() {
        Ok(()) => {},
        Err(e) => {
            error!("Couldn't drop privileges. {}", e);
            warn!("Running as root");
        }
    }

    for thread in threads {
        let _ = thread.join();
    }

}


fn main() {
    let matches = App::new("dhcpd")
            .version("1.0")
            .author("Markus Ongyerth")
            .about("A simple home users dhcp server")
            .arg(Arg::with_name("config")
                 .short("c")
                 .long("config")
                 .value_name("FILE")
                 .help("Path to config file to be used")
                 .takes_value(true))
            .get_matches();

    let path = matches.value_of("dhcpd").unwrap_or("/etc/dhcp/dhcpd.conf");

    run_server(path);
}
