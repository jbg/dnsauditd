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

struct State {}

impl State {
    pub fn new() -> State {
        State {}
    }
}

fn process_name(pid: u32) -> Option<String> {
    match File::open(Path::new("/proc").join(format!("{}", pid)).join("comm")) {
        Ok(mut file) => {
            let mut contents = String::new();
            match file.read_to_string(&mut contents) {
                Ok(_) => Some(contents.trim().to_string()),
                Err(_) => None
            }
        },
        Err(_) => None
    }
}

fn handle_dns(pid: Option<u32>, payload: &[u8]) {
    let proc_name = if let Some(pid) = pid { if let Some(name) = process_name(pid) { name } else { "[err]".to_string() } } else { "[?]".to_string() };
    match dns_parser::Packet::parse(payload) {
        Ok(packet) => {
            for question in packet.questions {
                println!("{}: {}/{:?}", proc_name, question.qname, question.qtype);
            }
        },
        Err(e) => println!("Malformed DNS message: {}", e)
    }
}

fn pid_listening_on_port(port: u16, proc_net_iter: &mut Iterator<Item=Result<String, std::io::Error>>) -> Option<u32> {
    let mut pid: Option<u32> = None;

    let src_port_hex = format!("{:X}", port);
    let mut sock_inode: Option<u32> = None;
    while let Some(line) = proc_net_iter.next() {
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
            if path.is_dir() {
                path.push("fd");
                if path.is_dir() {
                    if let Ok(entries) = read_dir(path) {
                        for entry in entries {
                            let path = entry.unwrap().path();
                            let dest = path.read_link().unwrap().into_os_string().into_string().unwrap();
                            if dest == lookup {
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

fn handle_udp(payload: &[u8], proc_net_iter: &mut Iterator<Item=Result<String, std::io::Error>>) {
    let packet = UdpPacket::new(payload).unwrap();
    let dst_port = packet.get_destination();
    if dst_port == 53 {
        let pid = pid_listening_on_port(packet.get_source(), proc_net_iter);
        handle_dns(pid, packet.payload());
    }
    else {
        println!("Unexpected destination port: {}", dst_port);
    }
}

fn handle_tcp(payload: &[u8], proc_net_iter: &mut Iterator<Item=Result<String, std::io::Error>>) {
    let packet = TcpPacket::new(payload).unwrap();
    let port = packet.get_destination();
    if port == 53 {
        let pid = pid_listening_on_port(packet.get_source(), proc_net_iter);
        let payload = packet.payload();
        if payload.len() > 0 {
            handle_dns(pid, &payload[2..]);
        }
    }
    else {
        println!("Unexpected destination port: {}", port);
    }
}

fn queue_callback(msg: &Message, _state: &mut State) {
    let payload = msg.get_payload();
    if msg.get_l3_proto() == 0x0800 {  // IPv4
        let packet = Ipv4Packet::new(payload).unwrap();
        match packet.get_next_level_protocol() {
            Udp => {
                let file = File::open("/proc/net/udp").unwrap();
                let mut reader = BufReader::new(file);
                let mut iter = reader.lines().skip(1);
                handle_udp(packet.payload(), &mut iter)
            },
            Tcp => {
                let file = File::open("/proc/net/tcp").unwrap();
                let mut reader = BufReader::new(file);
                let mut iter = reader.lines().skip(1);
                handle_tcp(packet.payload(), &mut iter)
            },
            _ => println!("Unexpected protocol: {}", packet.get_next_level_protocol())
        }
    }
    else {
        let packet = Ipv6Packet::new(payload).unwrap();
        match packet.get_next_header() {
            Udp => {
                let file = File::open("/proc/net/udp6").unwrap();
                let mut reader = BufReader::new(file);
                let mut iter = reader.lines().skip(1);
                handle_udp(packet.payload(), &mut iter)
            },
            Tcp => {
                let file = File::open("/proc/net/tcp6").unwrap();
                let mut reader = BufReader::new(file);
                let mut iter = reader.lines().skip(1);
                handle_tcp(packet.payload(), &mut iter)
            },
            _ => println!("Unexpected protocol: {}", packet.get_next_header())
        }
    }
    msg.set_verdict(Verdict::Accept);
}

fn main() {
    println!("dnsauditd 0.1");

    let mut q = Queue::new(State::new());
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
