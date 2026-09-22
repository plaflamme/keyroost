use keyroost_piv::Slot;
use ssh_agent_lib::{
    error::AgentError as SshAgentError,
    proto::{Identity, PublicCredential},
    ssh_key::{
        public::{EcdsaPublicKey, Ed25519PublicKey, KeyData},
        sec1::EncodedPoint,
    },
};
use std::path::Path;
use tokio::net::UnixListener;

mod error;
mod piv;

pub use error::AgentError;

pub use crate::piv::PivSshAgent;

#[derive(Clone)]
pub struct KeyroostAgent {
    piv: piv::PivSshAgent,
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for KeyroostAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, SshAgentError> {
        Ok(self.piv.list_identities()?)
    }
}

pub async fn run(socket_path: &Path, piv: PivSshAgent) -> Result<(), AgentError> {
    let listener = UnixListener::bind(socket_path)?;
    ssh_agent_lib::agent::listen(listener, KeyroostAgent { piv }).await?;
    Ok(())
}
