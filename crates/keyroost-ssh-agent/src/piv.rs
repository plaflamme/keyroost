use keyroost_piv::{
    x509::{SigHash, X509Error},
    KeyAlg, PublicKey, Slot,
};
use keyroost_transport::PivSession;
use sha2::Digest;
use ssh_agent_lib::{
    proto::{Identity, PublicCredential},
    ssh_key::{
        public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey},
        sec1::EncodedPoint,
        Mpint, Signature,
    },
};
use zeroize::Zeroizing;

use crate::AgentError;

struct PivIdentity {
    slot: Slot,
    key_alg: KeyAlg,
    ssh_identity: Identity,
}

impl From<PivIdentity> for Identity {
    fn from(value: PivIdentity) -> Self {
        value.ssh_identity
    }
}

#[derive(Clone)]
pub struct PivSshAgent {
    reader: String,
    pin: Zeroizing<String>, // TODO: pinentry
    slots: Vec<Slot>,
}

impl PivSshAgent {
    // TODO: manually select slots
    pub fn new(reader: String, pin: Zeroizing<String>) -> Self {
        // default signature-related slots
        let sign_slots: &[Slot] = &[
            Slot::Authentication,
            Slot::CardAuthentication,
            Slot::Signature,
        ];

        Self {
            reader,
            pin,
            slots: Vec::from_iter([sign_slots, &Slot::retired_all()].concat()),
        }
    }

    pub(super) fn request_identities(&self) -> Result<Vec<Identity>, AgentError> {
        let mut session = keyroost_transport::PivSession::open(&self.reader)
            .map_err(AgentError::TransportError)?;
        let identities = self.list_identities(&mut session)?;
        Ok(identities.into_iter().map(Into::into).collect())
    }

    pub(super) fn sign(
        &self,
        public_credential: PublicCredential,
        data: &[u8],
    ) -> Result<Option<Signature>, AgentError> {
        let mut session = keyroost_transport::PivSession::open(&self.reader)
            .map_err(AgentError::TransportError)?;

        let piv_identity = self
            .list_identities(&mut session)?
            .into_iter()
            .find(|id| id.ssh_identity.credential == public_credential);

        let Some(piv_identity) = piv_identity else {
            return Ok(None);
        };

        // TODO: pinentry, slot policy
        session.verify_pin(self.pin.as_bytes())?;

        let sig_hash = match keyroost_piv::x509::signature_hash(piv_identity.key_alg) {
            Ok(sig_hash) => sig_hash,
            Err(X509Error::UnsupportedAlgorithm) => return Ok(None),
            Err(other) => return Err(AgentError::Other(Box::new(other))),
        };

        let prepared = match sig_hash {
            SigHash::Sha256 => sha2::Sha256::digest(data).to_vec(),
            SigHash::Sha384 => sha2::Sha384::digest(data).to_vec(),
            SigHash::None => data.to_vec(),
        };

        let signature = session.sign(piv_identity.slot, piv_identity.key_alg, &prepared)?;

        let signature = match piv_identity.key_alg {
            KeyAlg::EccP256 => Signature::try_from(
                ecdsa::Signature::<p256::NistP256>::from_der(&signature)
                    .map_err(|e| AgentError::Other(Box::new(e)))?,
            ),
            KeyAlg::EccP384 => Signature::try_from(
                ecdsa::Signature::<p384::NistP384>::from_der(&signature)
                    .map_err(|e| AgentError::Other(Box::new(e)))?,
            ),
            _ => todo!(),
        };

        Ok(Some(signature?))
    }

    fn list_identities<'a: 'b, 'b>(
        &'a self,
        session: &'b mut PivSession,
    ) -> Result<impl Iterator<Item = PivIdentity> + 'b, AgentError> {
        Ok(self.slots.iter().flat_map(|slot| {
            // TODO: deal with Err here, probably logging is sufficient
            slot_to_ssh_identity(session, *slot).ok().flatten()
        }))
    }
}

fn slot_to_ssh_identity(
    session: &mut PivSession,
    slot: Slot,
) -> Result<Option<PivIdentity>, AgentError> {
    let Some(cert) = session.read_certificate(slot)? else {
        return Ok(None);
    };

    let (key_alg, public_key) = keyroost_piv::x509_parse::parse_certificate_public_key(&cert)?;

    Ok(Some(PivIdentity {
        slot,
        key_alg,
        ssh_identity: Identity {
            credential: ssh_public_credentials(key_alg, public_key)?,
            comment: format!("PIV {slot:?}"),
        },
    }))
}

fn ssh_public_credentials(
    key_alg: KeyAlg,
    public_key: PublicKey,
) -> Result<PublicCredential, AgentError> {
    let key_data = match public_key {
        PublicKey::Rsa { modulus, exponent } => KeyData::Rsa(RsaPublicKey {
            n: Mpint::from_bytes(&modulus)?,
            e: Mpint::from_bytes(&exponent)?,
        }),
        PublicKey::Ecc { point } => match key_alg {
            KeyAlg::EccP256 => {
                KeyData::Ecdsa(EcdsaPublicKey::NistP256(EncodedPoint::from_bytes(&point)?))
            }
            KeyAlg::EccP384 => {
                KeyData::Ecdsa(EcdsaPublicKey::NistP384(EncodedPoint::from_bytes(&point)?))
            }
            KeyAlg::Ed25519 => KeyData::Ed25519(Ed25519PublicKey::try_from(point.as_slice())?),
            KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
                return Err(AgentError::SshKeyError(
                    ssh_agent_lib::ssh_key::Error::PublicKey,
                ))
            }
            KeyAlg::X25519 => {
                // NOTE: this is technically unreachable because keyroost_piv::x509::signature_hash will already have returned "not supported"
                return Err(AgentError::SshKeyError(
                    ssh_agent_lib::ssh_key::Error::AlgorithmUnknown,
                ));
            }
        },
    };
    Ok(PublicCredential::Key(key_data))
}
