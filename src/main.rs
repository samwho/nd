extern crate pnet;

mod icmp;

use std::env;
use std::error;
use std::net;
use std::str::FromStr;

type Result<T> = std::result::Result<T, Box<error::Error>>;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err((format!("Usage: {} ip", args[0])).into());
    }

    let mut icmp_client = icmp::IcmpClient::new();
    let trace_to = net::Ipv4Addr::from_str(&args[1])?;

    for ttl in 1..255 {
        icmp_client.send_echo_request(trace_to, ttl, 2)?;
        match icmp_client.recv_packet() {
            Some(packet) => {
                println!("{:?}", packet);
                if packet.get_src() == trace_to {
                    break;
                }
            }
            None => println!("no response for ttl {}", ttl),
        };
    }

    Ok(())
}
