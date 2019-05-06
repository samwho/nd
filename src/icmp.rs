use pnet::packet::icmp;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::Packet;
use pnet::packet::PrimitiveValues;
use pnet::transport::{
  ipv4_packet_iter, transport_channel, TransportChannelType::Layer3, TransportSender,
};
use std::error;
use std::net;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

type Result<T> = std::result::Result<T, Box<error::Error>>;

pub struct IcmpClient {
  tx: TransportSender,
  rx: mpsc::Receiver<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct IcmpData {
  src: net::Ipv4Addr,
  dst: net::Ipv4Addr,
  icmp_type: u8,
  icmp_code: u8,
  identifier: u16,
  sequence_number: u16,
}

impl IcmpData {
  fn new(bytes: Vec<u8>) -> Self {
    let ipv4_packet = ipv4::Ipv4Packet::new(&bytes).unwrap();
    let icmp_packet = icmp::IcmpPacket::new(&bytes[20..]).unwrap();

    let mut data = IcmpData {
      src: ipv4_packet.get_source(),
      dst: ipv4_packet.get_destination(),
      icmp_type: icmp_packet.get_icmp_type().to_primitive_values().0,
      icmp_code: icmp_packet.get_icmp_code().to_primitive_values().0,
      identifier: 0,
      sequence_number: 0,
    };

    match icmp_packet.get_icmp_type() {
      icmp::IcmpTypes::TimeExceeded => {
        let te = icmp::time_exceeded::TimeExceededPacket::new(icmp_packet.packet()).unwrap();
        let inner_v4 = ipv4::Ipv4Packet::new(te.payload()).unwrap();
        let inner_request = icmp::echo_request::EchoRequestPacket::new(inner_v4.payload()).unwrap();
        data.identifier = inner_request.get_identifier();
        data.sequence_number = inner_request.get_sequence_number();
      }
      icmp::IcmpTypes::EchoReply => {
        let er = icmp::echo_reply::EchoReplyPacket::new(icmp_packet.packet()).unwrap();
        data.identifier = er.get_identifier();
        data.sequence_number = er.get_sequence_number();
      }
      _ => (),
    };

    data
  }

  pub fn get_src(&self) -> net::Ipv4Addr {
    self.src
  }

  pub fn get_dst(&self) -> net::Ipv4Addr {
    self.dst
  }

  pub fn get_type(&self) -> u8 {
    self.icmp_type
  }

  pub fn get_code(&self) -> u8 {
    self.icmp_code
  }

  pub fn get_identifier(&self) -> u16 {
    self.identifier
  }

  pub fn get_sequence_number(&self) -> u16 {
    self.sequence_number
  }
}

impl IcmpClient {
  pub fn new() -> Self {
    let (sender, rx) = mpsc::channel();
    thread::spawn(move || {
      let (_, mut rx) = transport_channel(1024, Layer3(IpNextHeaderProtocols::Icmp)).unwrap();
      let mut iter = ipv4_packet_iter(&mut rx);
      loop {
        match iter.next() {
          Ok((packet, _)) => match sender.send(packet.packet().to_owned()) {
            Ok(()) => {}
            Err(_) => {
              drop(sender);
              break;
            }
          },
          Err(_) => {
            drop(sender);
            break;
          }
        }
      }
    });

    let (tx, _) = transport_channel(1024, Layer3(IpNextHeaderProtocols::Icmp)).unwrap();
    IcmpClient { tx, rx }
  }

  pub fn send_echo_request(
    &mut self,
    dest: net::Ipv4Addr,
    ttl: u8,
    identifier: u16,
  ) -> Result<usize> {
    let mut ipv4_packet_buffer = [0u8; 32];
    let mut icmp_packet_buffer = [0u8; 12];

    let mut ipv4_packet = ipv4::MutableIpv4Packet::new(&mut ipv4_packet_buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(32);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(dest);
    ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));

    let mut icmp_packet =
      icmp::echo_request::MutableEchoRequestPacket::new(&mut icmp_packet_buffer).unwrap();
    icmp_packet.set_icmp_type(icmp::IcmpTypes::EchoRequest);
    icmp_packet.set_identifier(identifier);
    icmp_packet.set_sequence_number(ttl as u16);

    let mut clone = icmp_packet.packet().clone();
    icmp_packet.set_checksum(icmp::checksum(&icmp::IcmpPacket::new(&mut clone).unwrap()));

    ipv4_packet.set_payload(icmp_packet.packet());

    self
      .tx
      .send_to(ipv4_packet, dest.into())
      .map_err(Into::into)
  }

  pub fn recv_packet(&mut self) -> Option<IcmpData> {
    self
      .rx
      .recv_timeout(Duration::from_millis(1000))
      .ok()
      .map(IcmpData::new)
  }
}
