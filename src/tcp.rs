use std::array::TryFromSliceError;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum TcpOptionType {
    EndOfOptionList,
    NoOperation,
    MaximumSegmentSize,
    WindowScale,
    SackPermitted,
    Timestamp,
    Other(u8),
}

impl From<u8> for TcpOptionType {
    fn from(raw: u8) -> Self {
        match raw {
            0 => TcpOptionType::EndOfOptionList,
            1 => TcpOptionType::NoOperation,
            2 => TcpOptionType::MaximumSegmentSize,
            3 => TcpOptionType::WindowScale,
            4 => TcpOptionType::SackPermitted,
            8 => TcpOptionType::Timestamp,
            other => TcpOptionType::Other(other),
        }
    }
}

#[derive(Debug)]
pub enum TcpOption {
    EndOfOptionList,
    NoOperation,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Timestamp(u32, u32),
    Other(u8),
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

struct TcpParsingError {
    message: String,
}

impl Error for TcpParsingError {}

impl fmt::Display for TcpParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl fmt::Debug for TcpParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!( f, "TcpParsingError {{ message: {} }}", self.message)
    }
}

pub fn parse_tcp_header(input: &[u8]) -> Result<(&[u8], TcpSegment), TryFromSliceError> {
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

fn parse_tcp_option(input: &[u8]) -> Result<(&[u8], TcpOption), Box<dyn Error>> {
    if input.len() == 0 {
        return Err(Box::new(TcpParsingError { message: "End of option list not found for tcp segment".to_string() } ))
    }
    let option_type = TcpOptionType::from(<u8>::try_from(input[0])?);
    let (_, input) = input.split_at(1);
    match option_type {
        TcpOptionType::EndOfOptionList => Ok((input, TcpOption::EndOfOptionList)),
        TcpOptionType::NoOperation => Ok((input, TcpOption::NoOperation)),
        TcpOptionType::MaximumSegmentSize => {
            let _length = <u8>::try_from(input[0])?;
            let mss =  u16::from_be_bytes(<[u8; 2]>::try_from(&input[1..3])?);
            let (_, input) = input.split_at(3);
            Ok((input, TcpOption::MaximumSegmentSize(mss)))
        },
        TcpOptionType::WindowScale => {
            let _length = <u8>::try_from(input[0])?;
            let shift_count = <u8>::try_from(input[1])?;
            let (_, input) = input.split_at(2);
            Ok((input, TcpOption::WindowScale(shift_count)))
        },
        TcpOptionType::SackPermitted => {
            let _length = <u8>::try_from(input[0])?;
            let (_, input) = input.split_at(1);
            Ok((input, TcpOption::SackPermitted))
        },
        TcpOptionType::Timestamp => {
            let _length = <u8>::try_from(input[0])?;
            let ts_val =  u32::from_be_bytes(<[u8; 4]>::try_from(&input[1..5])?);
            let ts_ecr =  u32::from_be_bytes(<[u8; 4]>::try_from(&input[5..9])?);
            let (_, input) = input.split_at(9);
            Ok((input, TcpOption::Timestamp(ts_val, ts_ecr)))
        },
        TcpOptionType::Other(kind) => Ok((input, TcpOption::Other(kind)))
    }
}

fn parse_tcp_options(input: &[u8]) -> Result<(&[u8], Vec<TcpOption>), Box<dyn Error>> {
    let mut rest = input;
    let mut options: Vec<TcpOption> = vec![];
    loop {
        match parse_tcp_option(rest) {
            Ok((r, option)) => {
                rest = r;
                match option {
                    TcpOption::EndOfOptionList => {
                        options.push(option);
                        break;
                    },
                    TcpOption::Other(_) => {
                        options.push(option);
                        break;
                    },
                    _ => { options.push(option) }
                }
                if rest.len() == 0 {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
    }

    Ok((rest, options))
}

pub fn parse_tcp(input: &[u8]) -> Result<(&[u8], TcpSegment), Box<dyn Error>> {
    match parse_tcp_header(input) {
        Ok((rest, mut segment)) => {
            if segment.header_length > 5 {
                let options_length = ((segment.header_length - 5) * 4) as usize;
                if options_length <= rest.len() {
                    if let Ok((_, options)) = parse_tcp_options(&rest[0..options_length]) {
                        segment.options = Some(options);
                        return Ok((&rest[options_length..], segment));
                    }
                    Ok((&rest[options_length..], segment))
                } else {
                    return Err(Box::new(TcpParsingError { message: "Bad TCP options".to_string() } ))
                }
            } else {
                Ok((rest, segment))
            }
        }
        Err(e) => Err(Box::new(e)),
    }
}
