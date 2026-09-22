use std::fmt::Display;

use keyroost_transport::TransportError;
use ssh_agent_lib::agent::Agent;

#[non_exhaustive]
#[derive(Debug)]
pub enum AgentError {
    /// An IO error
    Io(std::io::Error),
    /// An SSH-agent application error
    SshError(String),
    // A Keyroost transport error
    TransportError(TransportError),

    PivInvalidKeyAlgorithm,
}

impl Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::SshError(error) => write!(f, "{error}"),
            Self::TransportError(transport_error) => write!(f, "{transport_error}"),
            Self::PivInvalidKeyAlgorithm => write!(f, "PivInvalidKeyAlgorithm"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<std::io::Error> for AgentError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ssh_agent_lib::error::AgentError> for AgentError {
    fn from(value: ssh_agent_lib::error::AgentError) -> Self {
        match value {
            ssh_agent_lib::error::AgentError::IO(error) => Self::Io(error),
            ssh_agent_lib::error::AgentError::Other(other) => {
                match other.downcast::<AgentError>() {
                    Ok(ae) => *ae,
                    Err(other) => Self::SshError(other.to_string()),
                }
            }
            other => Self::SshError(other.to_string()),
        }
    }
}
impl From<AgentError> for ssh_agent_lib::error::AgentError {
    fn from(value: AgentError) -> Self {
        ssh_agent_lib::error::AgentError::Other(Box::new(value))
    }
}

impl From<TransportError> for AgentError {
    fn from(value: TransportError) -> Self {
        Self::TransportError(value)
    }
}
