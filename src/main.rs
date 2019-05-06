extern crate pnet;

mod icmp;

use std::collections::HashMap;
use std::env;
use std::error;
use std::net;
use std::str::FromStr;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<error::Error>>;

#[derive(Clone, Debug)]
struct PingResult {
    ttl: u8,
    duration: Duration,
    icmp: Option<icmp::IcmpData>,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err((format!("Usage: {} ip", args[0])).into());
    }

    let mut icmp_client = icmp::IcmpClient::new();
    let trace_to = net::Ipv4Addr::from_str(&args[1])?;

    let mut results: HashMap<u8, Vec<PingResult>> = HashMap::new();
    for ttl in 1..255 {
        results.insert(ttl, Vec::with_capacity(20));
    }

    loop {
        for ttl in 1..255 {
            let now = Instant::now();
            icmp_client.send_echo_request(trace_to, ttl, 2)?;

            let icmp_result = icmp_client.recv_packet();
            let should_break = if let Some(p) = &icmp_result {
                p.get_src() == trace_to
            } else {
                false
            };

            results.get_mut(&ttl).unwrap().push(PingResult {
                ttl: ttl,
                duration: now.elapsed(),
                icmp: icmp_result,
            });

            if should_break {
                break;
            }
        }

        print_results(&results);
    }

    Ok(())
}

fn print_results(results: &HashMap<u8, Vec<PingResult>>) {
    let mut keys: Vec<&u8> = results.keys().collect();
    keys.sort();

    for key in keys {
        let pings = results.get(key).unwrap();
        if pings.len() == 0 {
            break;
        }

        let mut ips: Vec<net::Ipv4Addr> = pings
            .iter()
            .filter(|p| p.icmp.is_some())
            .map(|p| p.icmp.as_ref().unwrap().get_src())
            .collect();

        ips.sort();
        ips.dedup();

        for ip in ips {
            println!(" {}  {} ", key, ip);
        }
    }
}
