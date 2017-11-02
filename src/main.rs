extern crate dns_parser;
extern crate libc;
extern crate nfqueue;
extern crate pnet;

use std::fs::{File, read_dir};
use std::io::BufReader;
use std::io::prelude::*;
use std::path::Path;

use libc::AF_INET;
use nfqueue::{CopyMode, Message, Queue, Verdict};
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols::{Tcp, Udp};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;


fn process_name(pid: Option<u32>) -> String {
    match pid { 
        Some(pid) => match File::open(Path::new("/proc").join(format!("{}", pid)).join("comm")) {
            Ok(mut file) => {
                let mut contents = String::new();
                match file.read_to_string(&mut contents) {
                    Ok(_) => contents.trim().to_string(),
                    Err(_) => "[err]".to_string()
                }
            },
            Err(_) => "[err]".to_string()
        },
        None => "[?]".to_string()
    }
}

fn handle_dns(pid: Option<u32>, payload: &[u8]) {
    match dns_parser::Packet::parse(payload) {
        Ok(packet) => {
            let proc_name = process_name(pid);
            for question in packet.questions {
                println!("{}: {}/{:?}", proc_name, question.qname, question.qtype);
            }
        },
        Err(e) => println!("Malformed DNS message: {}", e)
    }
}

fn pid_listening_on_port(port: u16, transport: &str) -> Option<u32> {
    let mut pid: Option<u32> = None;

    let src_port_hex = format!("{:X}", port);
    let mut sock_inode: Option<u32> = None;

    let file = File::open(Path::new("/proc/net").join(transport)).unwrap();
    let reader = BufReader::new(file);
    let mut iter = reader.lines().skip(1);
    while let Some(line) = iter.next() {
        match line {
            Ok(line) => {
                let parts: Vec<&str> = line.split_whitespace().collect();
                match parts[1].split(":").nth(1) {
                    Some(candidate) => if src_port_hex == candidate {
                        sock_inode = Some(parts[9].parse().unwrap());
                        break
                    },
                    None => println!("Failed to parse line: {}", line)
                }
            },
            Err(_) => break
        }
    }

    if let Some(inode) = sock_inode {
        let lookup = format!("socket:[{}]", inode);
        'proc_loop: for entry in read_dir("/proc").unwrap() {
            let pid_entry = entry.unwrap();
            let mut path = pid_entry.path();
            path.push("fd");
            if path.is_dir() {
                if let Ok(entries) = read_dir(path) {
                    for entry in entries {
                        let path = entry.unwrap().path();
                        if let Ok(dest) = path.read_link() {
                            if dest.into_os_string().into_string().unwrap() == lookup {
                                pid = pid_entry.file_name().into_string().unwrap().parse().ok();
                                break 'proc_loop;
                            }
                        }
                    }
                }
            }
        }
    }

    pid
}

fn handle_udp(payload: &[u8], transport: &str) {
    let packet = UdpPacket::new(payload).unwrap();
    let dst_port = packet.get_destination();
    if dst_port == 53 {
        handle_dns(pid_listening_on_port(packet.get_source(), transport), packet.payload());
    }
}

fn handle_tcp(payload: &[u8], transport: &str) {
    let packet = TcpPacket::new(payload).unwrap();
    let dst_port = packet.get_destination();
    if dst_port == 53 {
        let payload = packet.payload();
        if payload.len() > 0 {
            handle_dns(pid_listening_on_port(packet.get_source(), transport), &payload[2..]);
        }
    }
}

struct State {}

fn queue_callback(msg: &Message, _state: &mut State) {
    let payload = msg.get_payload();
    if msg.get_l3_proto() == 0x0800 {  // IPv4
        let packet = Ipv4Packet::new(payload).unwrap();
        match packet.get_next_level_protocol() {
            Udp => handle_udp(packet.payload(), "udp"),
            Tcp => handle_tcp(packet.payload(), "tcp"),
            _ => {}
        }
    }
    else {
        let packet = Ipv6Packet::new(payload).unwrap();
        match packet.get_next_header() {
            Udp => handle_udp(packet.payload(), "udp6"),
            Tcp => handle_tcp(packet.payload(), "tcp6"),
            _ => {}
        }
    }
    msg.set_verdict(Verdict::Accept);
}

fn main() {
    println!("dnsauditd 0.1");

    let mut q = Queue::new(State {});
    q.open();
    q.unbind(AF_INET); // failure doesn't matter here

    let rc = q.bind(AF_INET);
    if rc != 0 {
        panic!("Failed to bind queue to AF_INET with error {}", rc);
    }
    q.create_queue(0, queue_callback);
    q.set_mode(CopyMode::CopyPacket, 0xffff);

    println!("ready");
    q.run_loop();

    q.close(); // never reached?
}
