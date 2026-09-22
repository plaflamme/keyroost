use std::fmt::Display;

use keyroost_transport::TransportError;
use ssh_agent_lib::{proto::Error as ProtoError, ssh_key};

#[non_exhaustive]
#[derive(Debug)]
pub enum AgentError {
    /// An IO error
    Io(std::io::Error),
    /// An SSH-agent application error
    SshAgentError(ssh_agent_lib::error::AgentError),
    SshKeyError(ssh_key::Error),
    // A Keyroost transport error
    TransportError(TransportError),
}

impl Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::SshAgentError(error) => write!(f, "{error}"),
            Self::SshKeyError(error) => write!(f, "{error}"),
            Self::TransportError(transport_error) => write!(f, "{transport_error}"),
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
        AgentError::SshAgentError(value)
    }
}

impl From<ssh_agent_lib::ssh_key::Error> for AgentError {
    fn from(value: ssh_agent_lib::ssh_key::Error) -> Self {
        AgentError::SshKeyError(value)
    }
}
impl From<AgentError> for ssh_agent_lib::error::AgentError {
    fn from(value: AgentError) -> Self {
        match value {
            AgentError::Io(error) => ssh_agent_lib::error::AgentError::IO(error),
            AgentError::SshAgentError(agent_error) => agent_error,
            AgentError::SshKeyError(error) => {
                ssh_agent_lib::error::AgentError::Proto(ProtoError::SshKey(error))
            }
            AgentError::TransportError(transport_error) => {
                ssh_agent_lib::error::AgentError::Other(Box::new(transport_error))
            }
        }
    }
}
impl From<TransportError> for AgentError {
    fn from(value: TransportError) -> Self {
        Self::TransportError(value)
    }
}
