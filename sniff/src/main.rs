use std::collections::HashMap;
use std::net::SocketAddr;

use colored::Colorize;
use pcap::{Device, Capture};
use pnet_packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{TcpPacket, TcpFlags},
    Packet,
};

use packet::{PacketType, PacketReader, Hello, PacketDecode};
use sniff::Rc4;

// NOTE: This is just a quick setup for sniffing stuff. I will eventually clean
// this up! <3

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Flow {
    server: SocketAddr,
    client: SocketAddr,
}

struct ParsedTcpFlags {
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
}

impl ParsedTcpFlags {
    fn from_packet(packet: &TcpPacket) -> Self {
        let flags = packet.get_flags();

        ParsedTcpFlags {
            syn: flags & TcpFlags::SYN != 0,
            ack: flags & TcpFlags::ACK != 0,
            fin: flags & TcpFlags::FIN != 0,
            rst: flags & TcpFlags::RST != 0,
        }
    }
}

impl Flow {
    fn from_packet(ip: &Ipv4Packet, tcp: &TcpPacket) -> Self {
        let src = SocketAddr::new(
            ip.get_source().into(),
            tcp.get_source(),
        );
        let dest = SocketAddr::new(
            ip.get_destination().into(),
            tcp.get_destination(),
        );

        let (client, server) = if tcp.get_source() == 2050 {
            (dest, src)
        } else {
            (src, dest)
        };

        Self { client, server, }
    }
}

#[derive(Debug, Clone)]
struct Connection {}

fn main() {
    // Get the default device.
    let dev = Device::lookup().unwrap().unwrap();
    println!("Will use device \"{}\"", dev.name);

    // Activate a capture for the device.
    let mut cap = Capture::from_device(dev)
        .unwrap()
        .snaplen(1 << 16)
        .promisc(true)
        .immediate_mode(true)
        .open()
        .unwrap();

    // Filter for RotMG packets.
    cap.filter("tcp port 2050", true)
        .expect("Couldn't configure a capture filter");

    let mut connections: HashMap<Flow, Connection> = HashMap::new();

    let mut prev_is_fin = false;

    let mut waiting_for_hello = true;

    println!("Waiting for initial Hello packet to start decrypting...");

    // Start capturing!
    while let Ok(packet) = cap.next_packet() {
        // We only care about TCP IPv4 packets.

        let Some(eth) = EthernetPacket::new(packet.data) else {
            continue;
        };

        if eth.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }

        let Some(ip) = Ipv4Packet::new(eth.payload()) else {
            continue;
        };

        if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            continue;
        }

        let Some(tcp) = TcpPacket::new(ip.payload()) else {
            continue;
        };

        let flow = Flow::from_packet(&ip, &tcp);
        let flags = ParsedTcpFlags::from_packet(&tcp);

        if flags.fin {
            prev_is_fin = true;
            println!("{}, expecting new flow", format!("FIN").green());
            continue;
        }

        if flags.rst {
            println!("{}, removing connection", format!("RST").green());
            connections.remove(&flow);
            println!("Living connections: {connections:?}");
            continue;
        }

        if flags.syn && !flags.ack {
            if prev_is_fin {
                print!("New connection after FIN: ");
                prev_is_fin = false;
            } else {
                print!("New connection without FIN: ");
            }

            println!("{}", format!("{flow:?}").to_uppercase().cyan());

            connections.insert(flow, Connection {});
        }

        let payload = tcp.payload();

        if payload.len() < 5 { continue; }

        let Some(packet_type) = PacketType::try_from(payload[4]).ok() else {
            continue;
        };

        if waiting_for_hello {
            if packet_type != PacketType::Hello { continue; }

            waiting_for_hello = false;

            println!("Got initial hello!");
        }

        if packet_type == PacketType::Hello {
            let mut data = payload[5..].iter().cloned().collect::<Vec<u8>>();
            let mut decryptor = Rc4::new_outgoing();
            decryptor.process(&mut data);
            let mut reader = PacketReader::new(&data);
            let hello = Hello::decode(&mut reader);
            println!("{hello:#?}");
        }

        let packet_type = Some(packet_type)
            .map(|p| format!("{:?}", p).into())
            .unwrap_or("Unknown".red());

        let below = "below".green();
        let above = "above".red();
        let size = if payload.len() < 1000 { below } else { above };

        println!(
            "Payload {} 1000 {:>4}: {:>2X?}: {} {}",
            size,
            payload.len(),
            &payload[..5],
            if tcp.get_source() == 2050 { "I".red() } else { "O".green() },
            packet_type,
        );
    }
}
