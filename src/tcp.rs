use std::array::TryFromSliceError;

const END_OF_OPTIONS: u8 = 0;
const NO_OP: u8 = 1;
const MSS: u8 = 2;
const WINDOW_SCALE: u8 = 3;
const SACK_PERMITTED: u8 = 4;

#[derive(Debug)]
pub enum TcpOption {
    EndOfOptions,
    NoOperation,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
}


#[derive(Debug)]
pub struct TcpSegment {
    pub source_port: u16,
    pub dest_port: u16,
    pub sequence_no: u32,
    pub ack_no: u32,
    pub header_length: u8,
    pub reserved: u8,
    pub flag_urg: bool,
    pub flag_ack: bool,
    pub flag_psh: bool,
    pub flag_rst: bool,
    pub flag_syn: bool,
    pub flag_fin: bool,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Option<Vec<TcpOption>>,
}

pub fn parse_tcp(input: &[u8]) -> Result<(&[u8], TcpSegment), TryFromSliceError> {
    let source_port = u16::from_be_bytes(<[u8; 2]>::try_from(&input[0..2])?);
    let dest_port = u16::from_be_bytes(<[u8; 2]>::try_from(&input[2..4])?);
    let sequence_no = u32::from_be_bytes(<[u8; 4]>::try_from(&input[4..8])?);
    let ack_no = u32::from_be_bytes(<[u8; 4]>::try_from(&input[8..12])?);

    let hlen_res_flags = u16::from_be_bytes(<[u8; 2]>::try_from(&input[12..14])?);
    let header_length = (hlen_res_flags >> 12) as u8;
    let reserved = ((hlen_res_flags >> 6) & 0b0000_0000_0011_1111) as u8; 
    let flags = (hlen_res_flags & 0b0000_0000_0011_1111) as u8; 

    let window = u16::from_be_bytes(<[u8; 2]>::try_from(&input[14..16])?);
    let checksum = u16::from_be_bytes(<[u8; 2]>::try_from(&input[16..18])?);
    let urgent_pointer = u16::from_be_bytes(<[u8; 2]>::try_from(&input[18..20])?);

    let (_, input) = input.split_at(20);

    let segment = TcpSegment {
            source_port,
            dest_port,
            sequence_no,
            ack_no,
            header_length,
            reserved,
            flag_urg: flags & 0b10_0000 == 0b10_0000,
            flag_ack: flags & 0b01_0000 == 0b01_0000,
            flag_psh: flags & 0b00_1000 == 0b00_1000,
            flag_rst: flags & 0b00_0100 == 0b00_0100,
            flag_syn: flags & 0b00_0010 == 0b00_0010,
            flag_fin: flags & 0b00_0001 == 0b00_0001,
            window,
            checksum,
            urgent_pointer,
            options: None,
        };

    Ok((
        input,
        segment
    ))
}
