//! Functions for getting the local LAN IP address.
use crate::{Result, sdk::device::DevicePublicKey};
use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use if_addrs::{get_if_addrs, IfAddr, Ifv4Addr};

/// Get v4 IP addresses that are not the loopback or link
/// local addresses.
pub fn v4_lan_ip_list() -> Result<Vec<Ifv4Addr>> {
    let addrs = get_if_addrs()?;
    let mut output = Vec::with_capacity(addrs.len());
    for net in addrs {
        if let IfAddr::V4(v4) = net.addr {
            if v4.is_loopback() || v4.is_link_local() {
                continue;
            }
            output.push(v4);
        }
    }
    Ok(output)
}

/// Get the first v4 IP address that is not a loopback
/// or link local address.
pub fn v4_lan_ip() -> Result<Option<Ifv4Addr>> {
    let mut ips = v4_lan_ip_list()?;
    Ok(if !ips.is_empty() {
        Some(ips.remove(0))
    } else {
        None
    })
}

/// Set of device public keys.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct DeviceSet(pub HashSet<DevicePublicKey>);
