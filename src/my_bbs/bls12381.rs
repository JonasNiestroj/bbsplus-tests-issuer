/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::my_bbs::utils::set_panic_hook;

use crate::{my_bbs::BbsVerifyResponse, my_bbs::PoKOfSignatureProofWrapper};
use bbs::prelude::*;
use pairing_plus::{
    bls12_381::{Bls12, Fr, G1, G2},
    hash_to_field::BaseFromRO,
    serdes::SerDes,
    CurveProjective,
};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::Error;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    iter::FromIterator,
};

pub struct BbsKeyPair {
    pub publicKey: PublicKey,
    pub secretKey: Option<SecretKey>,
    messageCount: usize,
}

pub struct BlsKeyPair {
    pub publicKey: Option<Vec<u8>>,
    pub secretKey: Option<SecretKey>,
}

pub struct BlsVerifyProofContext {
    pub proof: PoKOfSignatureProofWrapper,
    pub publicKey: DeterministicPublicKey,
    pub messages: Vec<Vec<u8>>,
    pub nonce: Vec<u8>,
}

pub struct BlsCreateProofRequest {
    pub signature: Signature,
    pub publicKey: DeterministicPublicKey,
    pub messages: Vec<Vec<u8>>,
    pub revealed: Vec<usize>,
    pub nonce: Vec<u8>,
}

pub struct BlsBbsVerifyRequest {
    pub publicKey: DeterministicPublicKey,
    pub signature: Signature,
    pub messages: Vec<Vec<u8>>,
}

pub struct BlsBbsSignRequest {
    pub keyPair: &'static BlsKeyPair,
    pub messages: Vec<Vec<u8>>,
}

pub struct Bls12381ToBbsRequest {
    pub keyPair: BlsKeyPair,
    pub messageCount: usize,
}

/// Generate a BLS 12-381 key pair.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (32 bytes)
/// followed by the public key (96) bytes.
pub async fn bls_generate_g2_key(seed: Option<Vec<u8>>) -> Result<BlsKeyPair, Error> {
    set_panic_hook();
    Ok(bls_generate_keypair::<G2>(seed))
}

/// Generate a BLS 12-381 key pair.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (32 bytes)
/// followed by the public key (48) bytes.
pub async fn bls_generate_g1_key(seed: Option<Vec<u8>>) -> Result<BlsKeyPair, Error> {
    set_panic_hook();
    Ok(bls_generate_keypair::<G1>(seed))
}

/// Get the BBS public key associated with the private key
pub async fn bls_to_bbs_key(request: Bls12381ToBbsRequest) -> Result<BbsKeyPair, BBSError> {
    set_panic_hook();
    if request.messageCount == 0 {
        return Err(BBSError::from_msg(
            BBSErrorKind::GeneralError {
                msg: "Failed to convert key".to_string(),
            },
            "Failed to convert key",
        ));
    }
    if let Some(dpk_bytes) = request.keyPair.publicKey {
        let dpk = DeterministicPublicKey::from(array_ref![dpk_bytes, 0, G2_COMPRESSED_SIZE]);
        let pk = dpk.to_public_key(request.messageCount)?;
        let key_pair = BbsKeyPair {
            publicKey: pk,
            secretKey: request.keyPair.secretKey,
            messageCount: request.messageCount,
        };
        Ok(key_pair)
    } else if let Some(s) = request.keyPair.secretKey {
        let (dpk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(s)));
        let pk = dpk.to_public_key(request.messageCount)?;
        let key_pair = BbsKeyPair {
            publicKey: pk,
            secretKey: Some(sk),
            messageCount: request.messageCount,
        };
        Ok(key_pair)
    } else {
        return Err(BBSError::from_msg(
            BBSErrorKind::GeneralError {
                msg: "No key is specified".to_string(),
            },
            "No key is specified",
        ));
    }
}

/// Signs a set of messages with a BLS 12-381 key pair and produces a BBS signature
pub async fn bls_sign(request: BlsBbsSignRequest) -> Result<Signature, &'static str> {
    set_panic_hook();
    let dpk_bytes = request.keyPair.publicKey.as_ref().unwrap();
    let dpk = DeterministicPublicKey::from(array_ref![dpk_bytes, 0, G2_COMPRESSED_SIZE]);
    let pk_res = dpk.to_public_key(request.messages.len());
    let pk;
    match pk_res {
        Err(_) => return Err("Failed to convert key"),
        Ok(p) => pk = p,
    };
    if request.keyPair.secretKey.is_none() {
        return Err("Failed to sign");
    }
    let messages: Vec<SignatureMessage> = request
        .messages
        .iter()
        .map(|m| SignatureMessage::hash(m))
        .collect();
    match Signature::new(
        messages.as_slice(),
        &request.keyPair.secretKey.as_ref().unwrap(),
        &pk,
    ) {
        Ok(sig) => Ok(sig),
        Err(e) => Err("I dont care11"),
    }
}

/// Verifies a BBS+ signature for a set of messages with a with a BLS 12-381 public key
pub async fn bls_verify(request: BlsBbsVerifyRequest) -> Result<BbsVerifyResponse, Error> {
    set_panic_hook();
    let res = request.try_into();
    let result: BlsBbsVerifyRequest;
    match res {
        Ok(r) => result = r,
        Err(e) => {
            return Ok(BbsVerifyResponse {
                verified: false,
                error: Some(format!("{:?}", e)),
            })
        }
    };
    if result.messages.is_empty() {
        return Ok(BbsVerifyResponse {
            verified: false,
            error: Some("Messages cannot be empty".to_string()),
        });
    }
    let pk = result
        .publicKey
        .to_public_key(result.messages.len())
        .unwrap();
    let messages: Vec<SignatureMessage> = result
        .messages
        .iter()
        .map(|m| SignatureMessage::hash(m))
        .collect();
    match result.signature.verify(messages.as_slice(), &pk) {
        Err(e) => Ok(BbsVerifyResponse {
            verified: false,
            error: Some(format!("{:?}", e)),
        }),
        Ok(b) => Ok(BbsVerifyResponse {
            verified: b,
            error: None,
        }),
    }
}

/// Creates a BBS+ PoK
pub async fn bls_create_proof(
    request: BlsCreateProofRequest,
) -> Result<PoKOfSignatureProofWrapper, &'static str> {
    set_panic_hook();
    if request.revealed.iter().any(|r| *r > request.messages.len()) {
        return Err("revealed value is out of bounds");
    }
    let pk = request
        .publicKey
        .to_public_key(request.messages.len())
        .unwrap();
    let revealed: BTreeSet<usize> = BTreeSet::from_iter(request.revealed.into_iter());
    let mut messages = Vec::new();
    for i in 0..request.messages.len() {
        if revealed.contains(&i) {
            messages.push(ProofMessage::Revealed(SignatureMessage::hash(
                &request.messages[i],
            )));
        } else {
            messages.push(ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(
                SignatureMessage::hash(&request.messages[i]),
            )));
        }
    }
    match PoKOfSignature::init(&request.signature, &pk, messages.as_slice()) {
        Err(e) => return Err("I dont care 15"),
        Ok(pok) => {
            let mut challenge_bytes = pok.to_bytes();
            if request.nonce.is_empty() {
                challenge_bytes.extend_from_slice(&[0u8; FR_COMPRESSED_SIZE]);
            } else {
                let nonce = ProofNonce::hash(&request.nonce);
                challenge_bytes.extend_from_slice(nonce.to_bytes_uncompressed_form().as_ref());
            }
            let challenge_hash = ProofChallenge::hash(&challenge_bytes);
            match pok.gen_proof(&challenge_hash) {
                Ok(proof) => {
                    let out =
                        PoKOfSignatureProofWrapper::new(request.messages.len(), &revealed, proof);
                    Ok(out)
                }
                Err(e) => Err("I dont care 16"),
            }
        }
    }
}

/// Verify a BBS+ PoK
pub async fn bls_verify_proof(
    request: BlsVerifyProofContext,
) -> Result<BbsVerifyResponse, &'static str> {
    set_panic_hook();
    let nonce = if request.nonce.is_empty() {
        ProofNonce::default()
    } else {
        ProofNonce::hash(&request.nonce)
    };
    let message_count = u16::from_be_bytes(*array_ref![request.proof.bit_vector, 0, 2]) as usize;
    let pk = request.publicKey.to_public_key(message_count).unwrap();
    let messages = request.messages.clone();
    let (revealed, proof) = request.proof.unwrap();
    if messages.len() != revealed.len() {
        return Ok(BbsVerifyResponse {
            verified: false,
            error: Some(format!(
                "Given messages count ({}) is different from revealed messages count ({}) for this proof",
                messages.len(),
                revealed.len()
            )),
        });
    }
    let proof_request = ProofRequest {
        revealed_messages: revealed,
        verification_key: pk,
    };

    let revealed_vec = proof_request
        .revealed_messages
        .iter()
        .collect::<Vec<&usize>>();
    let mut revealed_messages = BTreeMap::new();
    for i in 0..revealed_vec.len() {
        revealed_messages.insert(
            *revealed_vec[i],
            SignatureMessage::hash(messages[i].clone()),
        );
    }

    let signature_proof = SignatureProof {
        revealed_messages,
        proof,
    };

    Ok(BbsVerifyResponse {
        verified: Verifier::verify_signature_pok(&proof_request, &signature_proof, &nonce).is_ok(),
        error: None,
    })
}

fn bls_generate_keypair<G: CurveProjective<Engine = Bls12, Scalar = Fr> + SerDes>(
    seed: Option<Vec<u8>>,
) -> BlsKeyPair {
    let seed_data = match seed {
        Some(s) => s.to_vec(),
        None => {
            let mut rng = thread_rng();
            let mut s = vec![0u8, 32];
            rng.fill_bytes(s.as_mut_slice());
            s
        }
    };

    let sk = gen_sk(seed_data.as_slice());
    let mut pk = G::one();
    pk.mul_assign(sk);

    let mut pk_bytes = Vec::new();
    pk.serialize(&mut pk_bytes, true).unwrap();

    let keypair = BlsKeyPair {
        publicKey: Some(pk_bytes),
        secretKey: Some(SecretKey::from(sk)),
    };
    keypair
}

fn gen_sk(msg: &[u8]) -> Fr {
    use sha2::digest::generic_array::{typenum::U48, GenericArray};
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
    // copy of `msg` with appended zero byte
    let mut msg_prime = Vec::<u8>::with_capacity(msg.len() + 1);
    msg_prime.extend_from_slice(msg.as_ref());
    msg_prime.extend_from_slice(&[0]);
    // `result` has enough length to hold the output from HKDF expansion
    let mut result = GenericArray::<u8, U48>::default();
    assert!(hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), &msg_prime[..])
        .expand(&[0, 48], &mut result)
        .is_ok());
    Fr::from_okm(&result)
}
