use crate::device_cache::{self, DeviceRecord};
use crate::parse_socket;
use anyhow::{Context, Result};
use clap::Args;
use std::fmt;
use std::net::SocketAddr;

/// Common selector args that can be reused by commands that operate on a single device.
#[derive(Debug, Clone, Args)]
pub struct DeviceSelectorArgs {
    /// Resolve by cached device ID.
    #[arg(long, value_name = "id")]
    pub id: Option<String>,
    /// Resolve by cached device name (model identifier).
    #[arg(long, value_name = "name")]
    pub name: Option<String>,
    /// Resolve by cached manufacturer string.
    #[arg(long, value_name = "manufacturer")]
    pub manufacturer: Option<String>,
    /// Explicit address override (bypass cache).
    #[arg(long, value_name = "ip:port")]
    pub addr: Option<String>,
    /// Match all devices (reserved for future use).
    #[arg(long)]
    pub all: bool,
    /// Positional fallback target (ID/name/address).
    #[arg(value_name = "target")]
    pub target: Option<String>,
}

/// Result of resolving a selector to a concrete address.
#[derive(Debug, Clone)]
pub struct ResolvedDevice {
    pub record: Option<DeviceRecord>,
    pub addr: SocketAddr,
}

/// Try to resolve selectors into a `ResolvedDevice`.
pub fn resolve_device(args: &DeviceSelectorArgs) -> Result<ResolvedDevice> {
    if let Some(addr) = args.addr.as_deref() {
        let address =
            parse_socket(addr).with_context(|| format!("invalid --addr value \"{}\"", addr))?;
        return Ok(ResolvedDevice {
            record: None,
            addr: address,
        });
    }

    let devices = device_cache::load_devices().context("failed to read device cache")?;

    if let Some(id) = args.id.as_ref() {
        return select_device(&devices, "--id", id, |record| record.matches_id(id))
            .map_err(|err| anyhow::anyhow!(err));
    }
    if let Some(name) = args.name.as_ref() {
        return select_device(&devices, "--name", name, |record| record.matches_name(name))
            .map_err(|err| anyhow::anyhow!(err));
    }
    if let Some(manufacturer) = args.manufacturer.as_ref() {
        return select_device(&devices, "--manufacturer", manufacturer, |record| {
            record.matches_manufacturer(manufacturer)
        })
        .map_err(|err| anyhow::anyhow!(err));
    }

    if let Some(target) = args.target.as_ref() {
        match select_device(&devices, "--id", target, |record| record.matches_id(target)) {
            Ok(resolved) => return Ok(resolved),
            Err(SelectorError::NoMatches { .. }) => (),
            Err(err) => return Err(anyhow::anyhow!(err)),
        }

        match select_device(&devices, "--name", target, |record| {
            record.matches_name(target)
        }) {
            Ok(resolved) => return Ok(resolved),
            Err(SelectorError::NoMatches { .. }) => (),
            Err(err) => return Err(anyhow::anyhow!(err)),
        }

        let address = parse_socket(target)
            .with_context(|| format!("\"{}\" is not a valid socket address", target))?;
        return Ok(ResolvedDevice {
            record: None,
            addr: address,
        });
    }

    Err(SelectorError::MissingTarget.into())
}

fn select_device<F>(
    devices: &[DeviceRecord],
    filter: &'static str,
    value: &str,
    matcher: F,
) -> Result<ResolvedDevice, SelectorError>
where
    F: Fn(&DeviceRecord) -> bool,
{
    let matches = devices
        .iter()
        .filter(|record| matcher(record))
        .cloned()
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Err(SelectorError::NoMatches {
            filter,
            value: value.to_string(),
        }),
        1 => match_cached_address(&matches[0], filter, value),
        _ => Err(SelectorError::MultipleMatches {
            filter,
            value: value.to_string(),
        }),
    }
}

fn match_cached_address(
    record: &DeviceRecord,
    filter: &'static str,
    value: &str,
) -> Result<ResolvedDevice, SelectorError> {
    let addr_str = record
        .last_addr
        .as_ref()
        .ok_or_else(|| SelectorError::MissingAddress {
            device_id: record.device_id.clone(),
            filter,
            value: value.to_string(),
        })?;
    let addr = parse_socket(addr_str).map_err(|err| SelectorError::InvalidCachedAddress {
        device_id: record.device_id.clone(),
        address: addr_str.clone(),
        source: err.to_string(),
    })?;
    Ok(ResolvedDevice {
        record: Some(record.clone()),
        addr,
    })
}

#[derive(Debug)]
pub enum SelectorError {
    NoMatches {
        filter: &'static str,
        value: String,
    },
    MultipleMatches {
        filter: &'static str,
        value: String,
    },
    MissingAddress {
        device_id: String,
        filter: &'static str,
        value: String,
    },
    InvalidCachedAddress {
        device_id: String,
        address: String,
        source: String,
    },
    MissingTarget,
}

impl fmt::Display for SelectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectorError::NoMatches { filter, value } => write!(
                f,
                "No devices matched selector \"{} {}\". Try `alpine discover` or use --addr <ip:port>.",
                filter, value
            ),
            SelectorError::MultipleMatches { filter, value } => write!(
                f,
                "Multiple devices match \"{} {}\". Use --id or --addr to disambiguate.",
                filter, value
            ),
            SelectorError::MissingAddress {
                device_id,
                filter,
                value,
            } => write!(
                f,
                "Device {} matched \"{} {}\" but has no cached address. Run `alpine discover` again or use --addr <ip:port>.",
                device_id, filter, value
            ),
            SelectorError::InvalidCachedAddress {
                device_id,
                address,
                source,
            } => write!(
                f,
                "Device {} has cached address \"{}\" which failed to parse: {}. Re-run `alpine discover` or specify --addr.",
                device_id, address, source
            ),
            SelectorError::MissingTarget => write!(
                f,
                "No target provided. Use --addr <ip:port> or selectors such as --id, --name, or --manufacturer."
            ),
        }
    }
}

impl std::error::Error for SelectorError {}
