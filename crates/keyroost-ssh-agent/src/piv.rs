use keyroost_piv::Slot;
use keyroost_transport::PivSession;
use ssh_agent_lib::{
    proto::{Identity, PublicCredential},
    ssh_key::{
        public::{EcdsaPublicKey, Ed25519PublicKey, KeyData},
        sec1::EncodedPoint,
    },
};

use crate::AgentError;

#[derive(Clone)]
pub struct PivSshAgent {
    reader: String,
    slots: Vec<Slot>,
}

impl PivSshAgent {
    pub fn new(reader: String) -> Self {
        // default signature-related slots
        let sign_slots: &[Slot] = &[
            Slot::Authentication,
            Slot::CardAuthentication,
            Slot::Signature,
        ];

        Self {
            reader,
            slots: Vec::from_iter([sign_slots, &Slot::retired_all()].concat()),
        }
    }

    pub(super) fn list_identities(&self) -> Result<Vec<Identity>, AgentError> {
        let mut session = keyroost_transport::PivSession::open(&self.reader)
            .map_err(AgentError::TransportError)?;

        Ok(self
            .slots
            .iter()
            .flat_map(|slot| slot_to_ssh_identity(&mut session, *slot))
            .collect())
    }
}

fn slot_to_ssh_identity(session: &mut PivSession, slot: Slot) -> Option<Identity> {
    if !session.slot_has_key(slot).unwrap_or(false) {
        return None;
    }
    let Ok((key_alg, public_key)) = session.slot_key(slot) else {
        return None;
    };

    let key_data = match public_key {
        keyroost_piv::PublicKey::Rsa {
            modulus: _,
            exponent: _,
        } => todo!(),
        keyroost_piv::PublicKey::Ecc { point } => match key_alg {
            keyroost_piv::KeyAlg::Rsa1024
            | keyroost_piv::KeyAlg::Rsa2048
            | keyroost_piv::KeyAlg::Rsa3072
            | keyroost_piv::KeyAlg::Rsa4096 => return None,
            keyroost_piv::KeyAlg::EccP256 => KeyData::Ecdsa(
                EcdsaPublicKey::NistP256(EncodedPoint::from_bytes(&point).unwrap()), // TODO
            ),
            keyroost_piv::KeyAlg::EccP384 => KeyData::Ecdsa(
                EcdsaPublicKey::NistP384(EncodedPoint::from_bytes(&point).unwrap()), // TODO
            ),
            keyroost_piv::KeyAlg::Ed25519 => KeyData::Ed25519(
                Ed25519PublicKey::try_from(point.as_slice()).unwrap(), // TODO
            ),
            keyroost_piv::KeyAlg::X25519 => return None,
        },
    };
    Some(Identity {
        credential: PublicCredential::Key(key_data),
        comment: format!("PIV {slot:?}"),
    })
}
