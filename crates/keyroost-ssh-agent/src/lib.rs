use ssh_agent_lib::{error::AgentError as SshAgentError, proto::Identity};
use std::path::Path;
use tokio::net::UnixListener;

mod error;

pub use error::AgentError;

#[derive(Clone)]
pub struct KeyroostAgent;

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for KeyroostAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, SshAgentError> {
        Ok(Vec::default())
    }
}

impl KeyroostAgent {
    pub async fn run(socket_path: &Path) -> Result<(), AgentError> {
        let listener = UnixListener::bind(socket_path)?;
        ssh_agent_lib::agent::listen(listener, KeyroostAgent).await?;
        Ok(())
    }
}
