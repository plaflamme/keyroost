use keyroost_piv::{x509::SigHash, KeyAlg, Slot};
use keyroost_transport::PivSession;
use sha2::Digest;
use ssh_agent_lib::{
    proto::{Identity, PublicCredential},
    ssh_key::{
        public::{EcdsaPublicKey, Ed25519PublicKey, KeyData},
        sec1::EncodedPoint,
        Algorithm, EcdsaCurve, Signature, SigningKey,
    },
};
use zeroize::Zeroizing;

use crate::AgentError;

struct PivIdentity {
    slot: Slot,
    key_alg: KeyAlg,
    ssh_algorithm: Algorithm,
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
    pin: Zeroizing<String>,
    slots: Vec<Slot>,
}

impl PivSshAgent {
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
        let sig_hash =
            keyroost_piv::x509::signature_hash(piv_identity.key_alg).expect("there's a sighash");
        let prepared = match sig_hash {
            SigHash::Sha256 => sha2::Sha256::digest(data).to_vec(),
            SigHash::Sha384 => sha2::Sha384::digest(data).to_vec(),
            _ => todo!(),
        };

        eprintln!("Signing with slot {:?}", piv_identity.slot);
        let signature = session
            .sign(piv_identity.slot, piv_identity.key_alg, &prepared)
            .inspect_err(|e| eprintln!("signature failed {e}"))?;
        let signature = match piv_identity.key_alg {
            KeyAlg::EccP256 => Signature::try_from(
                ecdsa::Signature::<p256::NistP256>::from_der(&signature)
                    .expect("valid EccP256 bytes"),
            ),
            KeyAlg::EccP384 => Signature::try_from(
                ecdsa::Signature::<p384::NistP384>::from_der(&signature)
                    .expect("valid EccP384 bytes"),
            ),
            _ => todo!(),
        };
        eprintln!("signed...");
        // TODO: make Signature::new() not fail :sob:
        Ok(Some(signature?))
    }

    fn list_identities<'a: 'b, 'b>(
        &'a self,
        session: &'b mut PivSession,
    ) -> Result<impl Iterator<Item = PivIdentity> + 'b, AgentError> {
        eprintln!("listing identities from PIV reader {}", self.reader);

        eprintln!("looking for identities");
        Ok(self
            .slots
            .iter()
            .flat_map(|slot| slot_to_ssh_identity(session, *slot)))
    }
}

fn slot_to_ssh_identity(session: &mut PivSession, slot: Slot) -> Option<PivIdentity> {
    eprint!("  in PIV slot {slot:?}: ");
    let Ok(cert) = session.read_certificate(slot) else {
        eprintln!("cannot read certificate");
        return None;
    };
    let Some(cert) = cert else {
        eprintln!("no certificate");
        return None;
    };
    let Ok((key_alg, public_key)) = keyroost_piv::x509_parse::parse_certificate_public_key(&cert)
    else {
        eprintln!("no metadata");
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
            | keyroost_piv::KeyAlg::Rsa4096 => {
                eprintln!("unsupported algorithm");
                Algorithm::Rsa { hash: None };

                return None;
            }
            keyroost_piv::KeyAlg::EccP256 => KeyData::Ecdsa(
                EcdsaPublicKey::NistP256(EncodedPoint::from_bytes(&point).unwrap()), // TODO
            ),
            keyroost_piv::KeyAlg::EccP384 => KeyData::Ecdsa(
                EcdsaPublicKey::NistP384(EncodedPoint::from_bytes(&point).unwrap()), // TODO
            ),
            keyroost_piv::KeyAlg::Ed25519 => KeyData::Ed25519(
                Ed25519PublicKey::try_from(point.as_slice()).unwrap(), // TODO
            ),
            keyroost_piv::KeyAlg::X25519 => {
                eprintln!("unsupported algorithm");
                return None;
            }
        },
    };
    let ssh_algorithm = match key_alg {
        KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
            Algorithm::Rsa { hash: None }
        }
        KeyAlg::EccP256 => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        KeyAlg::EccP384 => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        KeyAlg::Ed25519 => Algorithm::Ed25519,
        KeyAlg::X25519 => unreachable!(),
    };
    eprintln!("found usable identity");
    Some(PivIdentity {
        slot,
        key_alg,
        ssh_algorithm,
        ssh_identity: Identity {
            credential: PublicCredential::Key(key_data),
            comment: format!("PIV {slot:?}"),
        },
    })
}
