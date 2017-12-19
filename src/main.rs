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

#[cfg(feature="dropcaps")]
extern crate caps;

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
use std::str::FromStr;

// This asumes linux! are there proper compile macros for this?
#[cfg(feature="dropcaps")]
fn drop_caps() -> std::io::Result<()> {
    info!("Droping capabilities");
    let pid = i32::from_str(std::fs::read_link("/proc/self")?.to_str().unwrap()).unwrap();

    let task_dirs = std::fs::read_dir("/proc/self/task")?;
    let tasks = task_dirs.map(|entry| match entry {
        Ok(e) => Ok(i32::from_str(e.file_name().to_str().unwrap()).unwrap()),
        Err(e) =>Err(e),
    });

    for task in tasks {
        match task {
            Ok(tid) => {
                if tid == pid {
                    continue;
                }

                trace!("Dropping caps for tid: {}", tid);

                let _ = caps::clear(Some(tid), caps::CapSet::Effective);
                let _ = caps::clear(Some(tid), caps::CapSet::Permitted);
            },
            Err(e) => {
                error!("Couldn't parse tid as u32: {}", e);
            }
        }
    }

    let _ = caps::clear(Some(pid), caps::CapSet::Effective);
    let _ = caps::clear(Some(pid), caps::CapSet::Permitted);

    Ok(())
}

#[cfg(not(feature = "dropcaps"))]
fn drop_caps() -> Result<(), String> {
    Err(String::from("This version was compiled without support for capabilities"))
}

// We could let the threads drop their own capabilities, at the right moment, but changing user
// will be per-process, not per-thread. So we first try that, then do a funny hack if that failed.
fn drop_user() {
    match privdrop::PrivDrop::default().user("dhcp").apply() {
        Ok(()) => {},
        Err(e) => {
            warn!("Running as root");

            if let Err(e2) = drop_caps() {
                error!("Couldn't drop user. {}", e);
                error!("Couldn't drop capabilities: {}", e2);
            }
        }
    }
}

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

    let cache_dir = conf.cache_dir;

    let threads: Vec<std::thread::JoinHandle<()>> =
            conf.interfaces.into_iter()
            .map(|iface| handler::handle_interface(iface, cache_dir.clone()))
            .collect();

    drop_user();

    for thread in threads {
        let _ = thread.join();
    }

}

fn verify_config(path: &str) {
    let conf: config::Config = rs_config::read_or_exit(path);

    println!("Conf: {:?}", conf);
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
            .arg(Arg::with_name("verify")
                 .long("verify")
                 .help("Verify the config and exit"))
            .get_matches();

    let path = matches.value_of("config").unwrap_or("/etc/dhcp/dhcpd.conf");

    if matches.is_present("verify") {
        verify_config(path);
    } else {
        run_server(path);
    }
}
