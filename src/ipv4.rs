use std::array::TryFromSliceError;
use std::convert::TryFrom;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub enum IPType {
    ICMP,
    TCP,
    UDP,
    Other(u8),
}

#[derive(Debug)]
pub struct IPv4Datagram {
    pub version: u8,
    pub header_length: u8,
    pub type_of_service: u8,
    pub length: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: IPType,
    pub header_checksum: u16,
    pub source_addr: Ipv4Addr,
    pub dest_addr: Ipv4Addr,
}

impl From<u8> for IPType {
    fn from(raw: u8) -> Self {
        match raw {
            1 => IPType::ICMP,
            6 => IPType::TCP,
            17 => IPType::UDP,
            other => IPType::Other(other),
        }
    }
}

pub fn parse_ipv4(input: &[u8]) -> Result<(&[u8], IPv4Datagram), TryFromSliceError> {
    let version_header_length = <u8>::try_from(input[0])?;
    let version = version_header_length >> 4;
    let header_length = version_header_length & 15;
    let type_of_service = <u8>::try_from(input[1])?;
    let length =  u16::from_be_bytes(<[u8; 2]>::try_from(&input[2..4])?);
    let id =  u16::from_be_bytes(<[u8; 2]>::try_from(&input[4..6])?);
    let flag_frag_offset =  u16::from_be_bytes(<[u8; 2]>::try_from(&input[6..8])?);
    let flags = (flag_frag_offset >> 13) as u8;
    let fragment_offset = flag_frag_offset & 8191;
    let ttl = <u8>::try_from(input[8])?;
    let protocol = IPType::from(<u8>::try_from(input[9])?);
    let header_checksum =  u16::from_be_bytes(<[u8; 2]>::try_from(&input[10..12])?);
    let source_addr = Ipv4Addr::from(<[u8; 4]>::try_from(&input[12..16])?);
    let dest_addr = Ipv4Addr::from(<[u8; 4]>::try_from(&input[16..20])?);

    let (_, input) = input.split_at(20);
    // let (_, input) = input.split_at(20 + ((header_length as i32 - 5)*4) as usize);
    let diagram = IPv4Datagram {
        version,
        header_length,
        type_of_service,
        length,
        id,
        flags,
        fragment_offset,
        ttl,
        protocol,
        header_checksum,
        source_addr,
        dest_addr,
    };
    Ok((input, diagram))
}
