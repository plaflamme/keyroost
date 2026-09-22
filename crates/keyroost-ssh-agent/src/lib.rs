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

use crate::piv::PivSshAgent;

#[derive(Clone)]
pub struct KeyroostAgent {
    piv: piv::PivSshAgent,
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for KeyroostAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, SshAgentError> {
        let readers = keyroost_transport::PivSession::list_piv_readers()
            .map_err(AgentError::TransportError)?;
        let name = readers.into_iter().next().unwrap(); // TODO
        let mut session =
            keyroost_transport::PivSession::open(&name).map_err(AgentError::TransportError)?;

        // default signature-related slots
        let sign_slots: &[Slot] = &[
            Slot::Authentication,
            Slot::CardAuthentication,
            Slot::Signature,
        ];

        let mut identities = Vec::new();
        for slot in [sign_slots, &Slot::retired_all()].concat() {
            if session.slot_has_key(slot).unwrap_or(false) {
                if let Ok((key_alg, public_key)) = session.slot_key(slot) {
                    let key_data = match public_key {
                        keyroost_piv::PublicKey::Rsa {
                            modulus: _,
                            exponent: _,
                        } => todo!(),
                        keyroost_piv::PublicKey::Ecc { point } => match key_alg {
                            keyroost_piv::KeyAlg::Rsa1024
                            | keyroost_piv::KeyAlg::Rsa2048
                            | keyroost_piv::KeyAlg::Rsa3072
                            | keyroost_piv::KeyAlg::Rsa4096 => {
                                return Err(SshAgentError::Other(Box::new(
                                    AgentError::PivInvalidKeyAlgorithm,
                                )))
                            }
                            keyroost_piv::KeyAlg::EccP256 => Some(KeyData::Ecdsa(
                                EcdsaPublicKey::NistP256(EncodedPoint::from_bytes(&point).unwrap()), // TODO
                            )),
                            keyroost_piv::KeyAlg::EccP384 => Some(KeyData::Ecdsa(
                                EcdsaPublicKey::NistP384(EncodedPoint::from_bytes(&point).unwrap()), // TODO
                            )),
                            keyroost_piv::KeyAlg::Ed25519 => Some(KeyData::Ed25519(
                                Ed25519PublicKey::try_from(point.as_slice()).unwrap(), // TODO
                            )),
                            keyroost_piv::KeyAlg::X25519 => None,
                        },
                    };
                    if let Some(key_data) = key_data {
                        identities.push(Identity {
                            credential: PublicCredential::Key(key_data),
                            comment: format!("PIV {slot:?}"),
                        });
                    }
                }
            }
        }
        Ok(identities)
    }
}

impl KeyroostAgent {
    pub async fn run(socket_path: &Path, piv: PivSshAgent) -> Result<(), AgentError> {
        let listener = UnixListener::bind(socket_path)?;
        ssh_agent_lib::agent::listen(listener, KeyroostAgent { piv }).await?;
        Ok(())
    }
}
