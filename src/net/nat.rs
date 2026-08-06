use igd::{search_gateway, PortMappingProtocol};
use std::net::SocketAddrV4;

pub enum NatStatus {
    UpnpMapped,
    Unreachable,
}

/// Attempts automatic UDP port forwarding on the local router using UPnP IGD.
pub fn try_upnp_port_forward(port: u16) -> Result<(), String> {
    match search_gateway(Default::default()) {
        Ok(gateway) => {
            let local_v4 = SocketAddrV4::new(*gateway.addr.ip(), port);
            gateway
                .add_port(
                    PortMappingProtocol::UDP,
                    port,
                    local_v4,
                    3600,
                    "randbotd P2P Gossip Daemon",
                )
                .map_err(|e| format!("UPnP port mapping failed: {}", e))?;
            Ok(())
        }
        Err(e) => Err(format!("No UPnP gateway found on local network: {}", e)),
    }
}

/// Performs a self-diagnosis check to verify if the listening socket is reachable.
pub fn diagnose_nat_reachability(port: u16) -> NatStatus {
    match try_upnp_port_forward(port) {
        Ok(_) => NatStatus::UpnpMapped,
        Err(e) => {
            println!("  -> UPnP Port Mapping Notice: {}", e);
            NatStatus::Unreachable
        }
    }
}
