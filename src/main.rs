use std::collections::BTreeSet;

use base64::{engine::general_purpose, Engine as _};
use bbs::prelude::SIGNATURE_COMPRESSED_SIZE;
use bbs::{prelude::DeterministicPublicKey, signature::Signature};
use my_bbs::prelude::BlsKeyPair;
use once_cell::sync::Lazy;
use rocket::tokio::sync::OnceCell;
use serde_json::{Map, Value};

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate arrayref;
mod my_bbs;

static KEY: Lazy<OnceCell<BlsKeyPair>> = Lazy::new(|| OnceCell::new());

#[post("/sd", data = "<input>")]
async fn sd(input: String) -> String {
    let dpk = DeterministicPublicKey::from(array_ref![
        KEY.get().unwrap().publicKey.as_ref().unwrap(),
        0,
        96
    ]);

    let v: Map<String, Value> = serde_json::from_str(input.as_str()).unwrap();
    let mut messages = Vec::new();

    let credential_data = v.get("credentialSubject").unwrap();

    let credential_subject = credential_data.as_object().unwrap();

    for (key, value) in credential_subject {
        println!(
            "{}",
            format!("{}: {}", key, value.to_string().replace("\"", ""))
        );
        messages.push(
            format!("{}: {}", key, value.to_string().replace("\"", ""))
                .as_bytes()
                .to_vec(),
        );
    }

    let proof_value = v.get("proof").unwrap().get("proofValue").unwrap().as_str();

    let encoded_proof_value = general_purpose::STANDARD_NO_PAD
        .decode(proof_value.unwrap().as_bytes())
        .unwrap();

    println!("{}", proof_value.unwrap());

    let sig = *array_ref![encoded_proof_value, 0, SIGNATURE_COMPRESSED_SIZE];

    let signature = Signature::from(sig);

    let mut revealed = Vec::new();
    revealed.push(1);
    revealed.push(2);

    let mut reveals = BTreeSet::new();
    reveals.insert(1);
    reveals.insert(2);

    let proof = my_bbs::bls12381::bls_create_proof(my_bbs::bls12381::BlsCreateProofRequest {
        messages: messages,
        publicKey: dpk,
        nonce: "nonce".as_bytes().to_vec(),
        signature: signature,
        revealed: revealed,
    })
    .await
    .unwrap();

    let mut value = proof.to_bytes();

    return general_purpose::STANDARD_NO_PAD.encode(value);
}

#[post("/", data = "<input>")]
async fn verify(input: String) -> String {
    println!("{}", input);
    let dpk = DeterministicPublicKey::from(array_ref![
        KEY.get().unwrap().publicKey.as_ref().unwrap(),
        0,
        96
    ]);
    let mut messages = Vec::new();
    let message = "{\"@context\":[\"https://schema.org\"],\"name\":\"Coursecredential\",\"description\":\"Coursecredentialdescription\",\"type\":[\"CourseCredential\"],\"credentialSubject\":{\"id\":\"did:key:z6MkfxQU7dy8eKxyHpG267FV23agZQu9zmokd8BprepfHALi\",\"givenName\":\"Chris\",\"familyName\":\"Shin\",\"educationalCredentialAwarded\":\"CertificateName\"},\"issuer\":{\"id\":\"did:web:organization.com\",\"name\":\"tenant\"},\"expirationDate\":\"2024-02-07T06:44:28.952Z\"}";
    //messages.push(input.as_bytes().to_vec());
    //messages.push(message.as_bytes().to_vec());

    let mut v: Map<String, Value> = serde_json::from_str(input.as_str()).unwrap();
    let cloned_v = v.clone();

    //let proof_value = &v["proof"]["proofValue"];

    let credential_data = cloned_v.get("credentialSubject").unwrap();

    let credential_subject = credential_data.as_object().unwrap();

    for (key, value) in credential_subject {
        println!(
            "{}",
            format!("{}: {}", key, value.to_string().replace("\"", ""))
        );
        messages.push(
            format!("{}: {}", key, value.to_string().replace("\"", ""))
                .as_bytes()
                .to_vec(),
        );
    }

    let proof_value = cloned_v
        .get("proof")
        .unwrap()
        .get("proofValue")
        .unwrap()
        .as_str();

    let encoded_proof_value = general_purpose::STANDARD_NO_PAD
        .decode(proof_value.unwrap().as_bytes())
        .unwrap();

    println!("{}", proof_value.unwrap());

    println!("{}", message);

    let proof =
        my_bbs::PoKOfSignatureProofWrapper::try_from(encoded_proof_value.as_slice()).unwrap();

    let verified = my_bbs::bls12381::bls_verify_proof(my_bbs::bls12381::BlsVerifyProofContext {
        publicKey: dpk,
        messages: messages,
        nonce: "nonce".as_bytes().to_vec(),
        proof: proof,
    })
    .await
    .unwrap();

    println!("{}", verified.verified);

    if verified.error.is_some() {
        println!("Error {}", verified.error.unwrap());
    }

    return verified.verified.to_string();
}

#[get("/")]
async fn index() -> String {
    let mut messages = Vec::new();
    let message = "{\"@context\":[\"https://schema.org\"],\"name\":\"Coursecredential\",\"description\":\"Coursecredentialdescription\",\"type\":[\"CourseCredential\"],\"credentialSubject\":{\"id\":\"did:key:z6MkfxQU7dy8eKxyHpG267FV23agZQu9zmokd8BprepfHALi\",\"givenName\":\"Jonas\",\"familyName\":\"Niestroj\"},\"issuer\":{\"id\":\"did:web:organization.com\",\"name\":\"tenant\"},\"expirationDate\":\"2024-02-07T06:44:28.952Z\"}";
    //messages.push(message.as_bytes().to_vec());
    messages.push(
        "id: did:key:z6MkfxQU7dy8eKxyHpG267FV23agZQu9zmokd8BprepfHALi"
            .as_bytes()
            .to_vec(),
    );
    messages.push("givenName: Jonas".as_bytes().to_vec());
    messages.push("familyName: Niestroj".as_bytes().to_vec());
    let sign_result: Result<bbs::signature::Signature, &str> =
        my_bbs::bls12381::bls_sign(my_bbs::bls12381::BlsBbsSignRequest {
            keyPair: KEY.get().unwrap(),
            messages: messages.clone(),
        })
        .await;
    let signature = sign_result.unwrap();

    let cred = format!(
        "{}, \"proof\": {{\"proofValue\": \"{}\"}}}}",
        &message[..&message.len() - 1],
        general_purpose::STANDARD_NO_PAD.encode(signature.to_bytes_compressed_form().to_vec())
    );

    return cred;

    /*let dpk = DeterministicPublicKey::from(array_ref![dpk_bytes, 0, 96]);
    /*let verified = my_bbs::bls12381::bls_verify(my_bbs::bls12381::BlsBbsVerifyRequest {
        publicKey: dpk,
        messages: messages,
        signature: signature,
    })
    .await
    .unwrap();*/
    let mut revealed = Vec::new();
    revealed.push(0);
    let proof = my_bbs::bls12381::bls_create_proof(my_bbs::bls12381::BlsCreateProofRequest {
        messages: messages.clone(),
        publicKey: dpk,
        signature: signature,
        revealed: revealed.clone(),
        nonce: "nonce".as_bytes().to_vec(),
    })
    .await
    .unwrap();

    let new_key_pair = my_bbs::bls12381::bls_generate_g2_key(None).await.unwrap();

    let bbs_key_pair = my_bbs::bls12381::bls_to_bbs_key(my_bbs::prelude::Bls12381ToBbsRequest {
        keyPair: new_key_pair,
        messageCount: 1,
    })
    .await
    .unwrap();
    let bbs_public_key = bbs_key_pair.publicKey.clone();
    let signature = my_bbs::bbs_plus::bbs_sign(my_bbs::bbs_plus::BbsSignRequest {
        keyPair: bbs_key_pair,
        messages: messages.clone(),
    })
    .await
    .unwrap();

    let bbs_proof = my_bbs::bbs_plus::bbs_create_proof(my_bbs::bbs_plus::CreateProofRequest {
        publicKey: bbs_public_key.clone(),
        messages: messages.clone(),
        nonce: "nonce".as_bytes().to_vec(),
        revealed: revealed.clone(),
        signature: signature.clone(),
    })
    .await
    .unwrap();

    let mut derived_messages = Vec::new();
    let derived_message = "{\"@context\":[\"https://schema.org\"],\"name\":\"Coursecredential\",\"description\":\"Coursecredentialdescription\",\"type\":[\"CourseCredential\"],\"credentialSubject\":{\"id\":\"did:key:z6MkfxQU7dy8eKxyHpG267FV23agZQu9zmokd8BprepfHALi\",\"givenName\":\"Chris\",\"familyName\":\"Shin\"},\"issuer\":{\"id\":\"did:web:organization.com\",\"name\":\"tenant\"},\"expirationDate\":\"2024-02-07T06:44:28.952Z\"}";
    derived_messages.push(derived_message.as_bytes().to_vec());

    let derived_proof = my_bbs::bbs_plus::bbs_create_proof(my_bbs::bbs_plus::CreateProofRequest {
        publicKey: bbs_public_key.clone(),
        messages: derived_messages.clone(),
        nonce: "nonce".as_bytes().to_vec(),
        revealed: revealed,
        signature: signature,
    })
    .await
    .unwrap();

    let verified = my_bbs::bbs_plus::bbs_verify_proof(my_bbs::bbs_plus::VerifyProofContext {
        messages: derived_messages,
        nonce: "nonce".as_bytes().to_vec(),
        proof: derived_proof,
        publicKey: bbs_public_key,
    })
    .await
    .unwrap()
    .verified;

    if verified {
        return "true".to_string();
    }
    "false".to_string()*/
}

#[launch]
async fn rocket() -> _ {
    let key = my_bbs::bls12381::bls_generate_g2_key(None).await.unwrap();
    KEY.set(key);
    rocket::build().mount("/", routes![index, verify, sd])
}
