use core::str::FromStr;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::errors::CliError;

#[derive(
    Default,
    ValueEnum,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Copy,
)]
#[repr(u8)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    #[default]
    Basic,
    Tcp,
    TcpTls,
    Quic,
}

impl TryFrom<u8> for Protocol {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Basic,
            1 => Self::Tcp,
            2 => Self::TcpTls,
            3 => Self::Quic,
            _ => return Err(()),
        })
    }
}

impl FromStr for Protocol {
    type Err = CliError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "basic" => Protocol::Basic,
            "tcp" => Protocol::Tcp,
            "tcp-tls" => Protocol::TcpTls,
            "quic" => Protocol::Quic,
            v => {
                return Err(CliError::ArgumentError(format!(
                    "Protocol {} is not available",
                    v
                )));
            }
        })
    }
}

impl Protocol {
    #[allow(unused_variables)]
    pub fn from(protocol_opt: Option<&str>) -> Result<Protocol, CliError> {
        let protocol = match protocol_opt {
            Some(s) => s.parse()?,
            None => Protocol::Basic,
        };
        Ok(protocol)
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quic => write!(f, "quic"),
            Self::Basic => write!(f, "basic"),
            Self::Tcp => write!(f, "tcp"),
            Self::TcpTls => write!(f, "tcp-tls"),
        }
    }
}
