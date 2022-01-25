use std::array::TryFromSliceError;

#[derive(Debug)]
pub enum Unreachable {
    DestinationNetworkUnreachable,
    DestinationHostUnreachable,
    DestinationProtocolUnreachable,
    DestinationPortUnreachable,
    FragmentationRequired,
    SourceRouteFailed,
    DestinationNetworkUnknown,
    DestinationHostUnknown,
    SourceHostIsolated,
    NetworkAdministrativelyProhibited,
    HostAdministrativelyProhibited,
    NetworkUnreachableForTos,
    HostUnreachableForTos,
    CommunicationAdministrativelyProhibited,
    HostPrecedenceViolation,
    PrecedentCutoffInEffect,
}

#[derive(Debug)]
pub enum Redirect {
    Network,
    Host,
    TosAndNetwork,
    TosAndHost,
}

#[derive(Debug)]
pub enum TimeExceeded {
    TTL,
    FragmentReassembly,
}

#[derive(Debug)]
pub enum ParameterProblem {
    Pointer,
    MissingRequiredOption,
    BadLength,
}

#[derive(Debug)]
pub enum ExtendedEchoReply {
    NoError,
    MalformedQuery,
    NoSuchInterface,
    NoSuchTableEntry,
    MupltipleInterfacesStatisfyQuery,
}

#[derive(Debug)]
pub enum IcmpCode {
    EchoReply,
    Reserved,
    DestinationUnreachable(Unreachable),
    SourceQuench,
    Redirect(Redirect),
    EchoRequest,
    RouterAdvertisment,
    RouterSolicication,
    TimeExceeded(TimeExceeded),
    ParameterProblem(ParameterProblem),
    Timestamp,
    TimestampReply,
    ExtendedEchoRequest,
    ExtendedEchoReply(ExtendedEchoReply),
    Other(u16),
}

impl From<u16> for IcmpCode {
    fn from(raw: u16) -> Self {
        let [t, c] = raw.to_be_bytes();
        match t {
            0x00 => Self::EchoReply,
            0x01 => Self::Reserved,
            0x02 => Self::Reserved,
            0x03 => match c {
                0x00 => Self::DestinationUnreachable(Unreachable::DestinationNetworkUnreachable),
                0x01 => Self::DestinationUnreachable(Unreachable::DestinationHostUnreachable),
                0x02 => Self::DestinationUnreachable(Unreachable::DestinationProtocolUnreachable),
                0x03 => Self::DestinationUnreachable(Unreachable::DestinationPortUnreachable),
                0x04 => Self::DestinationUnreachable(Unreachable::FragmentationRequired),
                0x05 => Self::DestinationUnreachable(Unreachable::SourceRouteFailed),
                0x06 => Self::DestinationUnreachable(Unreachable::DestinationNetworkUnknown),
                0x07 => Self::DestinationUnreachable(Unreachable::DestinationHostUnknown),
                0x08 => Self::DestinationUnreachable(Unreachable::SourceHostIsolated),
                0x09 => {
                    Self::DestinationUnreachable(Unreachable::NetworkAdministrativelyProhibited)
                }
                0x0A => Self::DestinationUnreachable(Unreachable::HostAdministrativelyProhibited),
                0x0B => Self::DestinationUnreachable(Unreachable::NetworkUnreachableForTos),
                0x0C => Self::DestinationUnreachable(Unreachable::HostUnreachableForTos),
                0x0D => Self::DestinationUnreachable(
                    Unreachable::CommunicationAdministrativelyProhibited,
                ),
                0x0E => Self::DestinationUnreachable(Unreachable::HostPrecedenceViolation),
                0x0F => Self::DestinationUnreachable(Unreachable::PrecedentCutoffInEffect),
                _ => Self::Other(raw),
            },
            0x04 => match c {
                0x00 => Self::SourceQuench,
                _ => Self::Other(raw),
            },
            0x05 => match c {
                0x00 => Self::Redirect(Redirect::Network),
                0x01 => Self::Redirect(Redirect::Host),
                0x02 => Self::Redirect(Redirect::TosAndNetwork),
                0x03 => Self::Redirect(Redirect::TosAndHost),
                _ => Self::Other(raw),
            },
            0x07 => Self::Reserved,
            0x08 => Self::EchoRequest,
            0x09 => Self::RouterAdvertisment,
            0x0A => Self::RouterSolicication,
            0x0B => match c {
                0x00 => Self::TimeExceeded(TimeExceeded::TTL),
                0x01 => Self::TimeExceeded(TimeExceeded::FragmentReassembly),
                _ => Self::Other(raw),
            },
            0x0C => match c {
                0x00 => Self::ParameterProblem(ParameterProblem::Pointer),
                0x01 => Self::ParameterProblem(ParameterProblem::MissingRequiredOption),
                0x02 => Self::ParameterProblem(ParameterProblem::BadLength),
                _ => Self::Other(raw),
            },
            0x0D => Self::Timestamp,
            0x0E => Self::TimestampReply,
            0x2A => Self::ExtendedEchoRequest,
            0x2B => match c {
                0x00 => Self::ExtendedEchoReply(ExtendedEchoReply::NoError),
                0x01 => Self::ExtendedEchoReply(ExtendedEchoReply::MalformedQuery),
                0x02 => Self::ExtendedEchoReply(ExtendedEchoReply::NoSuchInterface),
                0x03 => Self::ExtendedEchoReply(ExtendedEchoReply::NoSuchTableEntry),
                0x04 => {
                    Self::ExtendedEchoReply(ExtendedEchoReply::MupltipleInterfacesStatisfyQuery)
                }
                _ => Self::Other(raw),
            },
            _ => Self::Other(raw),
        }
    }
}

#[derive(Debug)]
pub struct IcmpPacket {
    pub code: IcmpCode,
    pub checksum: u16,
}

pub fn parse_icmp(input: &[u8]) -> Result<(&[u8], IcmpPacket), TryFromSliceError> {
    let code =  IcmpCode::from(u16::from_be_bytes(<[u8; 2]>::try_from(&input[0..2])?));
    let checksum = u16::from_be_bytes(<[u8; 2]>::try_from(&input[2..4])?);

    let (_, input) = input.split_at(4);
    let packet = IcmpPacket {
            code,
            checksum,
        };

    Ok((
        input,
        packet
    ))
}
