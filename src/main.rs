mod ethernet;
mod ipv4;
mod tcp;
mod udp;
mod arp;
mod icmp;
use pcap::Capture;
use std::error::Error;


fn main() -> Result<(), Box<dyn Error>> {
    // let mut cap = Capture::from_file("wlp5s0").unwrap().open().unwrap();
    let mut cap = Capture::from_file("aol-packets.pcap").unwrap();
    while let Ok(packet) = cap.next() {
        let (payload, frame) = ethernet::parse_ethernet(packet.data)?;
        println!("{:x?}", frame);

        match frame.ethertype {
            ethernet::EtherType::IPv4 => {
                let (payload, datagram) = ipv4::parse_ipv4(payload)?;
                println!("{:x?}", datagram);
            },
            ethernet::EtherType::ARP => {
                let (payload, packet) = arp::parse_arp(payload)?;
                println!("{:x?}", packet);
            }
            _ => {}
        }

    }
    Ok(())
}
