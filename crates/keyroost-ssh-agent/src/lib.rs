use ssh_agent_lib::{
    error::AgentError as SshAgentError,
    proto::{Identity, SignRequest},
    ssh_key::Signature,
};
use std::path::Path;
use tokio::net::UnixListener;
use tracing::debug;

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
        debug!("request_identities");
        Ok(self.piv.request_identities()?)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, SshAgentError> {
        debug!("sign({:?})", request.credential); // TODO: saner display
        let signature = self.piv.sign(request.credential, &request.data)?;
        let Some(signature) = signature else {
            return Err(SshAgentError::Failure); // TODO: what error should we return for "not found"?
        };
        Ok(signature)
    }
}

pub async fn run(socket_path: &Path, piv: PivSshAgent) -> Result<(), AgentError> {
    let listener = UnixListener::bind(socket_path)?;
    ssh_agent_lib::agent::listen(listener, KeyroostAgent { piv }).await?;
    Ok(())
}
