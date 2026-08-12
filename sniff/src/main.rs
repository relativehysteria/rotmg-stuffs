use std::collections::HashMap;
use std::net::SocketAddr;

use colored::Colorize;
use pcap::{Device, Capture};
use pnet_packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet},
    tcp::{TcpPacket, TcpFlags},
    Packet as _,
};

use packet::{
    PacketIo, PacketType, Direction,
    types,
};

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
    fn from_packet(ip: &Ipv4Packet, tcp: &TcpPacket) -> (Self, Direction) {
        // Create the source and destination addresses.
        let src = SocketAddr::new(
            ip.get_source().into(),
            tcp.get_source(),
        );
        let dest = SocketAddr::new(
            ip.get_destination().into(),
            tcp.get_destination(),
        );

        // Get the direction of the packet.
        let direction = (tcp.get_source() == 2050)
            .then_some(Direction::Incoming)
            .unwrap_or(Direction::Outgoing);

        // Determine who's the client and who's the server.
        let (client, server) = matches!(direction, Direction::Incoming)
            .then_some((dest, src))
            .unwrap_or((src, dest));

        (Self { client, server, }, direction)
    }
}

#[derive(Debug, Clone)]
struct Connection {}

fn main() {
    // Attempt to parse the device to use from environment, otherwise select the
    // one pcap chooses.
    let default_dev = Device::lookup().unwrap().unwrap();

    let dev_name = std::env::var("ROTMG_DEV").unwrap_or(default_dev.name);

    let devices = Device::list().unwrap();
    let dev_name = devices.iter()
        .find(|d| d.name == dev_name)
        .map(|d| d.name.clone())
        .expect("Device specified by ROTMG_DEV not found");

    println!("Devices on the system ({} will be selected):", dev_name.green());
    devices.iter().for_each(|d| println!(" * {}", d.name));

    let dev = devices.into_iter().find(|d| d.name == dev_name).unwrap();

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

    let mut packet_io = PacketIo::new();

    // Start capturing!
    println!("\nWaiting for initial Hello packet to start decrypting...");

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

        let (flow, direction) = Flow::from_packet(&ip, &tcp);
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

        // When we start sniffing, we have to wait for a Hello packet to start
        // decrypting...
        if waiting_for_hello {
            if packet_type != PacketType::Hello { continue; }
            waiting_for_hello = false;
        }

        let packet_len = payload.len();
        let (header, payload) = payload.split_at(5);
        match packet_type {
            PacketType::Hello => {
                // Hello packets mean the connection and its RC4 state is reset.
                packet_io.reset_rc4();

                let hello = packet_io.decode::<types::Hello>(
                    direction, payload);
                println!("{hello:#?}");
            },
            _ => {
                // Even if we don't recognize this packet, we have to process it
                // to keep the RC4 state in sync.
                packet_io
                    .rc4_for_direction(direction)
                    .discard(payload.len());
            },
        }


        let packet_type = Some(packet_type)
            .map(|p| format!("{:?}", p).into())
            .unwrap_or("Unknown".red());

        let size_text = (packet_len < 1000)
            .then_some("below".green())
            .unwrap_or("above".red());

        let dir_text = matches!(direction, Direction::Incoming)
            .then_some("I".red())
            .unwrap_or("O".green());

        println!(
            "Packet {} 1000 {:>4}: {:>2X?}: {} {}",
            size_text,
            packet_len,
            header,
            dir_text,
            packet_type,
        );
    }
}
