# Mohole
> Sniffing packets like a mole! A simple packet sniffer with virtually no dependencies written in Rust.


## Table of Contents
- [Introduction](#Introduction)
- [Usage Guide](#Usage-Guide)
- [See Also](#see-also)

## Introduction
This code parses the headers of packets obtained from `pcap`. It uses [pcap](https://crates.io/crates/pcap) which is a packet capture API around pcap/wpcap.pcap is the only dependency.

The following protocols are supported:
* Ethernet
* ARP
* IPv4
* ICMP
* TCP
* UDP
The implementations by no means try to cover the entire specification for each protocol. This code is meant to be used for educational purposes only.

## Usage Guide
You can listen for packets from a device
```rust
    let mut cap = Capture::from_device("wlp5s0").unwrap().open().unwrap();
```
or from a pcap dump file
```rust
    let mut cap = Capture::from_file("packets.pcap").unwrap();
```
There are other possible ways to capture packets, which are described in [pcap](https://crates.io/crates/pcap) documentation.
If you want to listen from a device you must first set the proper capabilities for the built executable.
```shell
cargo build
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/mohole
./target/debug/mohole
```

## See Also
The implementation of some of the parsers were inspired by the following repository:
* [pktparse](https://github.com/bestouff/pktparse-rs)

