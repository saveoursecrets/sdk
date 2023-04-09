//! Functions for getting the local LAN IP address and
//! information about the device.
use crate::Result;
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

/// Encapsulates information about a device.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// The user's full name.
    pub realname: String,
    /// The user name.
    pub username: String,
    /// The name of the device.
    pub device_name: String,
    /// The hostname or IP address.
    pub hostname: String,
    /// The platform identifier.
    pub platform: whoami::Platform,
    /// The platform distro.
    pub distro: String,
    /// The platform architecture.
    pub arch: whoami::Arch,
    /// The desktop environment.
    pub desktop_env: whoami::DesktopEnv,
}

impl DeviceInfo {
    /// Create new device info.
    pub fn new() -> Self {
        Self {
            realname: whoami::realname(),
            username: whoami::username(),
            device_name: whoami::devicename(),
            hostname: whoami::hostname(),
            platform: whoami::platform(),
            distro: whoami::distro(),
            arch: whoami::arch(),
            desktop_env: whoami::desktop_env(),
        }
    }
}
