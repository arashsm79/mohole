use std::array::TryFromSliceError;

pub type MacAddress = [u8;6];

#[derive(Debug)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    Other(u16),
}

#[derive(Debug)]
pub struct EthernetFrame {
    pub source_mac: MacAddress,
    pub dest_mac: MacAddress,
    pub ethertype: EtherType,
}

impl From<u16> for EtherType {
    fn from(raw: u16) -> Self {
        match raw {
            0x0800 => Self::IPv4,           
            0x86DD => Self::IPv6, 
            0x0806 => Self::ARP,            
            other => Self::Other(other),
        }
    }
}

pub fn parse_ethernet(input: &[u8]) -> Result<(&[u8], EthernetFrame), TryFromSliceError> {
    let dest_mac = MacAddress::try_from(&input[0..6])?;

    let source_mac = MacAddress::try_from(&input[6..12])?;

    let ether_type_bytes = <[u8; 2]>::try_from(&input[12..14])?;

    let (_, input) = input.split_at(14);

    let ethertype: EtherType = EtherType::from(u16::from_be_bytes(ether_type_bytes));
    let frame = EthernetFrame {
        dest_mac,
        source_mac,
        ethertype
    };
    Ok((input, frame))
}
