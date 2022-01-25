use std::net::Ipv4Addr;
use std::error::Error;
use crate::ethernet::MacAddress;

#[derive(Debug)]
pub enum HardwareType {
    Ethernet,
    Other(u16),
}

#[derive(Debug)]
pub enum ProtocolType {
    IPv4,
    Other(u16),
}

impl From<u16> for HardwareType {
    fn from(raw: u16) -> Self {
        match raw {
            0x0001 => Self::Ethernet,
            other => Self::Other(other),
        }
    }
}

impl From<u16> for ProtocolType {
    fn from(raw: u16) -> Self {
        match raw {
            0x0800 => Self::IPv4,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug)]
pub enum Operation {
    Request,
    Reply,
    Other(u16),
}

impl From<u16> for Operation {
    fn from(raw: u16) -> Self {
        match raw {
            0x0001 => Self::Request,
            0x0002 => Self::Reply,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug)]
pub struct ArpPacket {
    pub hw_type: HardwareType,
    pub protocol_type: ProtocolType,
    pub hw_size: u8,
    pub protocol_size: u8,
    pub operation: Operation,
    pub src_mac: MacAddress,
    pub src_addr: Ipv4Addr,
    pub dest_mac: MacAddress,
    pub dest_addr: Ipv4Addr,
}

pub fn parse_arp(input: &[u8]) -> Result<(&[u8], ArpPacket), Box<dyn Error>> {
    let hw_type =  HardwareType::from(u16::from_be_bytes(<[u8; 2]>::try_from(&input[0..2])?));
    let protocol_type =  ProtocolType::from(u16::from_be_bytes(<[u8; 2]>::try_from(&input[2..4])?));
    let hw_size = <u8>::try_from(input[4])?;
    let protocol_size = <u8>::try_from(input[5])?;
    let operation =  Operation::from(u16::from_be_bytes(<[u8; 2]>::try_from(&input[6..8])?));

    let src_mac = MacAddress::try_from(&input[8..12])?;
    let src_addr = Ipv4Addr::from(<[u8; 4]>::try_from(&input[12..16])?);
    let dest_mac = MacAddress::try_from(&input[16..20])?;
    let dest_addr = Ipv4Addr::from(<[u8; 4]>::try_from(&input[20..24])?);

    let (_, input) = input.split_at(24);
    // let (_, input) = input.split_at(20 + ((header_length as i32 - 5)*4) as usize);
    let packet = ArpPacket { hw_type, protocol_type, hw_size, protocol_size, operation, src_mac, src_addr, dest_mac, dest_addr };
    Ok((input, packet))
}
