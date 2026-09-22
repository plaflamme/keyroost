#[non_exhaustive]
#[derive(Debug)]
pub enum AgentError {
    /// An IO error
    Io(std::io::Error),
    /// An SSH-agent application error
    SshError(String),
}

impl From<std::io::Error> for AgentError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ssh_agent_lib::error::AgentError> for AgentError {
    fn from(value: ssh_agent_lib::error::AgentError) -> Self {
        match value {
            ssh_agent_lib::error::AgentError::IO(error) => Self::Io(error),
            other => Self::SshError(other.to_string()),
        }
    }
}
