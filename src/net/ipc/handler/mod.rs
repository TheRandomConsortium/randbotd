pub mod ca;
pub mod crl;
pub mod custodian;
pub mod offer;
pub mod peer;
pub mod proof;
pub mod purge;
pub mod rotation;

pub use ca::CaHandler;
pub use crl::CrlHandler;
pub use custodian::CustodianHandler;
pub use offer::OfferHandler;
pub use peer::PeerHandler;
pub use proof::ProofHandler;
pub use purge::PurgeHandler;
pub use rotation::RotationHandler;

use crate::crypto::identity::NodeIdentity;
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::net::phonebook::Phonebook;
use crate::storage::db::Database;
use std::sync::{Arc, RwLock};

/// Context provided to domain-specific IPC Command Handlers
pub struct IpcContext<'a> {
    pub phonebook: &'a Arc<RwLock<Phonebook>>,
    pub db: Option<&'a Arc<Database>>,
    pub identity: Option<&'a NodeIdentity>,
}

impl<'a> IpcContext<'a> {
    pub fn new(
        phonebook: &'a Arc<RwLock<Phonebook>>,
        db: Option<&'a Arc<Database>>,
        identity: Option<&'a NodeIdentity>,
    ) -> Self {
        Self {
            phonebook,
            db,
            identity,
        }
    }
}

/// Domain-specific IPC Command Handler Trait
///
/// Enables modular decomposition of IPC command handling logic across domain areas
/// (Peers, CAs, Offers, Domain Proofs, and future Cert / WoT handlers).
pub trait IpcHandler: Send + Sync {
    /// Attempts to process an incoming IPC command.
    ///
    /// Returns `Some(IpcResponse)` if the command is handled by this domain handler,
    /// or `None` if the command belongs to another domain.
    fn handle(&self, command: &IpcCommand, ctx: &IpcContext) -> Option<IpcResponse>;
}

/// Extensible Registry of IPC Domain Handlers
pub struct IpcHandlerRegistry {
    handlers: Vec<Box<dyn IpcHandler>>,
}

impl Default for IpcHandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcHandlerRegistry {
    /// Instantiates the default registry with all core domain handlers:
    /// - `PeerHandler`
    /// - `CaHandler`
    /// - `OfferHandler`
    /// - `ProofHandler`
    /// - `CrlHandler`
    /// - `PurgeHandler`
    pub fn new() -> Self {
        Self {
            handlers: vec![
                Box::new(PeerHandler),
                Box::new(CaHandler),
                Box::new(OfferHandler),
                Box::new(ProofHandler),
                Box::new(CrlHandler),
                Box::new(PurgeHandler),
                Box::new(RotationHandler),
                Box::new(CustodianHandler),
            ],
        }
    }

    /// Registers an additional domain handler (e.g. future CertHandler, PurgeHandler, etc.)
    #[allow(dead_code)]
    pub fn register(&mut self, handler: Box<dyn IpcHandler>) {
        self.handlers.push(handler);
    }

    /// Dispatches an IPC command across all registered domain handlers
    pub fn dispatch(&self, command: &IpcCommand, ctx: &IpcContext) -> IpcResponse {
        for handler in &self.handlers {
            if let Some(resp) = handler.handle(command, ctx) {
                return resp;
            }
        }
        IpcResponse::Error {
            reason: format!("No handler registered for command: {:?}", command),
        }
    }
}

/// Dispatches and executes IPC commands against local phonebook, database, and node identity
pub fn handle_ipc_command(
    command: IpcCommand,
    phonebook: &Arc<RwLock<Phonebook>>,
    db: Option<&Arc<Database>>,
    identity: Option<&NodeIdentity>,
) -> IpcResponse {
    let registry = IpcHandlerRegistry::new();
    let ctx = IpcContext::new(phonebook, db, identity);
    registry.dispatch(&command, &ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCustomHandler;
    impl IpcHandler for MockCustomHandler {
        fn handle(&self, _command: &IpcCommand, _ctx: &IpcContext) -> Option<IpcResponse> {
            Some(IpcResponse::Ok {
                message: "handled by mock custom handler".to_string(),
            })
        }
    }

    #[test]
    fn test_ipc_handler_registry_custom_registration() {
        let phonebook = Arc::new(RwLock::new(Phonebook::new()));
        let mut registry = IpcHandlerRegistry {
            handlers: Vec::new(),
        };

        let cmd = IpcCommand::ImportPeer {
            peer_addr: "1.2.3.4:5678".to_string(),
        };
        let ctx = IpcContext::new(&phonebook, None, None);

        // Initially no handlers
        let resp = registry.dispatch(&cmd, &ctx);
        match resp {
            IpcResponse::Error { reason } => {
                assert!(reason.contains("No handler registered"));
            }
            _ => panic!("Expected error for empty registry"),
        }

        // Register custom handler
        registry.register(Box::new(MockCustomHandler));
        let resp2 = registry.dispatch(&cmd, &ctx);
        match resp2 {
            IpcResponse::Ok { message } => {
                assert_eq!(message, "handled by mock custom handler");
            }
            _ => panic!("Expected Ok from mock handler"),
        }
    }
}
