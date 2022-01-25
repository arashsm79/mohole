use std::array::TryFromSliceError;

#[derive(Debug)]
pub struct UdpDatagram {
    pub source_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub checksum: u16,
}

pub fn parse_udp(input: &[u8]) -> Result<(&[u8], UdpDatagram), TryFromSliceError> {
    let source_port = u16::from_be_bytes(<[u8; 2]>::try_from(&input[0..2])?);
    let dest_port = u16::from_be_bytes(<[u8; 2]>::try_from(&input[2..4])?);
    let length = u16::from_be_bytes(<[u8; 2]>::try_from(&input[4..6])?);
    let checksum = u16::from_be_bytes(<[u8; 2]>::try_from(&input[6..8])?);

    let datagram = UdpDatagram { source_port, dest_port, length, checksum };

    Ok((
        input,
        datagram
    ))
}
