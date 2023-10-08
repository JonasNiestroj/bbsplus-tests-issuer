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

use crate::{
    my_bbs::bls12381::BbsKeyPair, my_bbs::BbsVerifyResponse, my_bbs::PoKOfSignatureProofWrapper,
};
use bbs::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    iter::FromIterator,
};

pub struct BbsSignRequest {
    pub keyPair: BbsKeyPair,
    pub messages: Vec<Vec<u8>>,
}

pub struct BbsVerifyRequest {
    publicKey: PublicKey,
    signature: Signature,
    messages: Vec<Vec<u8>>,
}

pub struct BlindSignatureContextRequest {
    publicKey: PublicKey,
    messages: Vec<Vec<u8>>,
    blinded: Vec<usize>,
    nonce: Vec<u8>,
}

pub struct BlindSignatureContextResponse {
    commitment: Commitment,
    proofOfHiddenMessages: ProofG1,
    challengeHash: ProofChallenge,
    blindingFactor: SignatureBlinding,
}

pub struct BlindSignatureVerifyContextRequest {
    commitment: Commitment,
    proofOfHiddenMessages: ProofG1,
    challengeHash: ProofChallenge,
    publicKey: PublicKey,
    blinded: BTreeSet<usize>,
    nonce: Vec<u8>,
}

pub struct BlindSignContextRequest {
    commitment: Commitment,
    publicKey: PublicKey,
    secretKey: SecretKey,
    messages: Vec<Vec<u8>>,
    known: Vec<usize>,
}

pub struct UnblindSignatureRequest {
    signature: BlindSignature,
    blindingFactor: SignatureBlinding,
}

pub struct CreateProofRequest {
    pub signature: Signature,
    pub publicKey: PublicKey,
    pub messages: Vec<Vec<u8>>,
    pub revealed: Vec<usize>,
    pub nonce: Vec<u8>,
}

pub struct VerifyProofContext {
    pub proof: PoKOfSignatureProofWrapper,
    pub publicKey: PublicKey,
    pub messages: Vec<Vec<u8>>,
    pub nonce: Vec<u8>,
}

pub async fn bbs_sign(request: BbsSignRequest) -> Result<Signature, &'static str> {
    let sk = request.keyPair.secretKey.ok_or("Error")?;
    let messages: Vec<SignatureMessage> = request
        .messages
        .iter()
        .map(|m| SignatureMessage::hash(m))
        .collect();
    match Signature::new(messages.as_slice(), &sk, &request.keyPair.publicKey) {
        Ok(sig) => Ok(sig),
        Err(_e) => Err("Failed to sign"),
    }
}

pub async fn bbs_verify(request: BbsVerifyRequest) -> Result<BbsVerifyResponse, BBSError> {
    let messages: Vec<SignatureMessage> = request
        .messages
        .iter()
        .map(|m| SignatureMessage::hash(m))
        .collect();
    match request
        .signature
        .verify(messages.as_slice(), &request.publicKey)
    {
        Ok(b) => Ok(BbsVerifyResponse {
            verified: b,
            error: None,
        }),
        Err(e) => Ok(BbsVerifyResponse {
            verified: false,
            error: Some(format!("{:?}", e)),
        }),
    }
}

pub async fn bbs_blind_signature_commitment(
    request: BlindSignatureContextRequest,
) -> Result<BlindSignatureContextResponse, &'static str> {
    set_panic_hook();
    if request.messages.len() != request.blinded.len() {
        return Err("messages.len() != blinded.len()");
    }
    if request
        .blinded
        .iter()
        .any(|b| *b > request.publicKey.message_count())
    {
        return Err("blinded value is out of bounds");
    }
    let mut messages = BTreeMap::new();
    for i in 0..request.blinded.len() {
        messages.insert(
            request.blinded[i],
            SignatureMessage::hash(&request.messages[i]),
        );
    }
    let nonce = ProofNonce::hash(&request.nonce);
    match Prover::new_blind_signature_context(&request.publicKey, &messages, &nonce) {
        Err(e) => Err("I dont care 10"),
        Ok((cx, bf)) => {
            let response = BlindSignatureContextResponse {
                commitment: cx.commitment,
                proofOfHiddenMessages: cx.proof_of_hidden_messages,
                challengeHash: cx.challenge_hash,
                blindingFactor: bf,
            };
            Ok(response)
        }
    }
}

pub async fn bbs_verify_blind_signature_proof(
    request: BlindSignatureVerifyContextRequest,
) -> Result<bool, &'static str> {
    set_panic_hook();

    let total = request.publicKey.message_count();
    if request.blinded.iter().any(|b| *b > total) {
        return Err("blinded value is out of bounds");
    }
    let messages = (0..total)
        .filter(|i| !request.blinded.contains(i))
        .collect();
    let nonce = ProofNonce::hash(&request.nonce);
    let ctx = BlindSignatureContext {
        commitment: request.commitment,
        challenge_hash: request.challengeHash,
        proof_of_hidden_messages: request.proofOfHiddenMessages,
    };
    match ctx.verify(&messages, &request.publicKey, &nonce) {
        Err(e) => Err("I dont care"),
        Ok(b) => Ok(b),
    }
}

pub async fn bbs_blind_sign(
    request: BlindSignContextRequest,
) -> Result<BlindSignature, &'static str> {
    set_panic_hook();

    if request.messages.len() != request.known.len() {
        return Err("messages.len() != known.len()");
    }
    if request
        .known
        .iter()
        .any(|k| *k > request.publicKey.message_count())
    {
        return Err("known value is out of bounds");
    }
    let messages: BTreeMap<usize, SignatureMessage> = request
        .known
        .iter()
        .zip(request.messages.iter())
        .map(|(k, m)| (*k, SignatureMessage::hash(m)))
        .collect();
    match BlindSignature::new(
        &request.commitment,
        &messages,
        &request.secretKey,
        &request.publicKey,
    ) {
        Ok(s) => Ok(s),
        Err(e) => Err("I dont care2"),
    }
}

pub async fn bbs_get_unblinded_signature(
    request: UnblindSignatureRequest,
) -> Result<Signature, &'static str> {
    set_panic_hook();

    Ok(request.signature.to_unblinded(&request.blindingFactor))
}

pub async fn bbs_create_proof(
    request: CreateProofRequest,
) -> Result<PoKOfSignatureProofWrapper, &'static str> {
    set_panic_hook();
    if request
        .revealed
        .iter()
        .any(|r| *r > request.publicKey.message_count())
    {
        return Err("revealed value is out of bounds");
    }
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
    match PoKOfSignature::init(&request.signature, &request.publicKey, messages.as_slice()) {
        Err(e) => {
            println!("{}", e.to_string());
            return Err("I dont care 3");
        }
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
                    let out = PoKOfSignatureProofWrapper::new(
                        request.publicKey.message_count(),
                        &revealed,
                        proof,
                    );
                    Ok(out)
                }
                Err(e) => Err("I dont care 4"),
            }
        }
    }
}

pub async fn bbs_verify_proof(
    request: VerifyProofContext,
) -> Result<BbsVerifyResponse, &'static str> {
    set_panic_hook();
    let nonce = if request.nonce.is_empty() {
        ProofNonce::default()
    } else {
        ProofNonce::hash(&request.nonce)
    };
    let messages = request.messages.clone();
    let (revealed, proof) = request.proof.unwrap();
    let proof_request = ProofRequest {
        revealed_messages: revealed,
        verification_key: request.publicKey,
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
