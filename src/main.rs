mod ethernet;
mod ipv4;
mod tcp;
mod udp;
mod arp;
mod icmp;
use pcap::Capture;
use std::error::Error;


fn main() -> Result<(), Box<dyn Error>> {
    // let mut cap = Capture::from_device("wlp5s0").unwrap().open().unwrap();
    let mut cap = Capture::from_file("aol-packets.pcap").unwrap();
    while let Ok(packet) = cap.next() {

        println!();
        if let Ok((payload, frame)) = ethernet::parse_ethernet(packet.data) {
            println!("{:x?}", frame);
            match frame.ethertype {
                ethernet::EtherType::IPv4 => {
                    if let Ok((payload, datagram)) = ipv4::parse_ipv4(payload) {
                        println!("{:?}", datagram);
                        match datagram.protocol {
                            ipv4::IPType::TCP => {
                                if let Ok((_payload, segment)) = tcp::parse_tcp(payload) {
                                    println!("{:?}", segment);
                                    if segment.dest_port == 80 || segment.source_port == 80 {
                                        println!("HTTP message.");
                                    } else if segment.dest_port == 443 || segment.source_port == 443 {
                                        println!("HTTPS message.");
                                    } else if segment.dest_port == 22 || segment.source_port == 22 {
                                        println!("SSH message.");
                                    }
                                } else {
                                    println!("Error parsing TCP segment.");
                                }
                            },
                            ipv4::IPType::UDP => {
                                if let Ok((_payload, udp_datagram)) = udp::parse_udp(payload) {
                                    println!("{:?}", udp_datagram);
                                    if udp_datagram.dest_port == 123 || udp_datagram.source_port == 123 {
                                        println!("NTP message.");
                                    } else if udp_datagram.dest_port == 443 || udp_datagram.source_port == 443 {
                                        println!("QUIC message.");
                                    }
                                } else {
                                        println!("Error parsing UDP datagram.");
                                    }
                            },
                            ipv4::IPType::ICMP => {
                                if let Ok((_payload, packet)) = icmp::parse_icmp(payload) {
                                    println!("{:?}", packet);
                                } else {
                                        println!("Error parsing ICMP packet.");
                                    }
                            },
                            _ => { println!("L4 protocol not supported")}
                        }
                    } else {
                        println!("Error parsing IP datagram.");
                    }
                },
                ethernet::EtherType::ARP => {
                    if let Ok((_payload, packet)) = arp::parse_arp(payload) {
                        println!("{:x?}", packet);
                    } else {
                        println!("Error parsing ARP packet.");
                    }
                }
                _ => { println!("L3 protocol not supported")}
            }
        } else {
            println!("Error parsing Ethernet frame.");
        }

    }
    Ok(())
}
