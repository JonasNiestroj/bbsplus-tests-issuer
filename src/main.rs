use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::marker::PhantomData;
use std::time::Duration;

use ark_bls12_381::{Bls12_381, Config, FrConfig, G1Affine};
use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_ff::{BigInt, Fp, MontBackend, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use base64::{engine::general_purpose, Engine as _};
use bbs::signature::Signature;
use bbs_plus::proof::{PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol};
use bbs_plus::proof_23::PoKOfSignature23G1Proof;
use bbs_plus::setup::{
    KeypairG1, KeypairG2, PreparedPublicKeyG2, PreparedSignatureParams23G1,
    PreparedSignatureParamsG1, PublicKeyG1, PublicKeyG2, SecretKey, SignatureParams23G1,
    SignatureParamsG1, SignatureParamsG2,
};
use bbs_plus::signature::{SignatureG1, SignatureG2};
use bbs_plus::signature_23::Signature23G1;
use blake2::Blake2b512;
use digest::Digest;
use futures::lock::Mutex;
use itertools::Itertools;
use lazy_static::lazy_static;
use once_cell::sync::Lazy;
use rand::thread_rng;
use rocket::data::FromData;
use rocket::http::{ContentType, RawStr, Status};
use rocket::serde::json::Json;
use rocket::tokio::sync::OnceCell;
use rocket::tokio::time::sleep;
use rocket_dyn_templates::{context, Template};
use schnorr_pok::compute_random_oracle_challenge;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate arrayref;

pub type Fr = <Bls12_381 as Pairing>::ScalarField;

#[derive(Serialize, Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CredentialProof {
    #[serde(rename = "type")]
    proof_type: String,
    created: String,
    verification_method: String,
    proof_purpose: String,
    proof_value: String,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Revocation {
    credential_index: u32,
    non_revocation_proof: Option<String>,
    non_revocation_challenge: Option<String>,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Credential {
    #[serde(rename = "@context")]
    context: Vec<String>,
    id: String,
    #[serde(rename = "type")]
    credential_type: Vec<String>,
    issuer: String,
    valid_from: String,
    credential_subject: Value,
    proof: CredentialProof,
    revocation: Revocation,
}

#[derive(Serialize, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Person {
    firstname: String,
    lastname: String,
    date_of_birth: String,
    country: String,
}

static KEY: Lazy<
    OnceCell<(
        PublicKeyG2<Bls12<Config>>,
        SecretKey<Fp<MontBackend<FrConfig, 4>, 4>>,
    )>,
> = Lazy::new(|| OnceCell::new());
static PARAMS: Lazy<OnceCell<SignatureParamsG1<Bls12<Config>>>> = Lazy::new(|| OnceCell::new());

lazy_static! {
    static ref OFFERS: Mutex<HashMap<String, HashMap<String, String>>> = Mutex::new(HashMap::new());
    static ref CREDENTIALS: Mutex<HashMap<String, Credential>> = Mutex::new(HashMap::new());
}

#[post("/sd", data = "<input>")]
async fn sd(input: String) -> String {
    /*let dpk = DeterministicPublicKey::from(array_ref![
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

    return general_purpose::STANDARD_NO_PAD.encode(value);*/
    return "".to_string();
}

#[post("/", data = "<input>")]
async fn verify(input: String) -> String {
    return "".to_string();
}

/*#[post("/offer")]
async fn offer() -> String {
    return "http://192.168.1.110:8080/credential".to_string();
}*/

#[post("/offer", format = "json", data = "<person>")]
async fn offer(person: Json<Person>) -> String {
    let id = Uuid::new_v4();
    let id_string = id.to_string();

    let mut map = OFFERS.lock().await;

    let mut values = HashMap::new();
    values.insert("dateOfBirth".to_string(), person.date_of_birth.to_string());
    values.insert("firstName".to_string(), person.firstname.to_string());
    values.insert("lastName".to_string(), person.lastname.to_string());
    //values.insert("country".to_string(), person.country.to_string());

    map.insert(id_string, values);

    return format!(
        "http://192.168.1.108:8000/credential?offer_id={}",
        id.to_string()
    );
}

#[post("/presentation", data = "<credential_string>")]
async fn presentation(credential_string: String) -> String {
    let credential: Credential =
        serde_json::from_str::<Credential>(credential_string.as_str()).unwrap();

    println!("{}", credential_string);

    let mut revealed_messages = BTreeMap::new();

    let mut index = 1;

    let credential_subject = credential.credential_subject.as_object().unwrap();

    // Use credential subject as messages
    for key in credential_subject.keys().sorted() {
        let msg = format!("{}: {}", key, credential_subject[key].as_str().unwrap());
        println!("msg {}", msg);
        let enc_msg = dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<
            Fr,
            Blake2b512,
        >(msg.as_bytes());

        revealed_messages.insert(index, enc_msg);
        index += 1;
    }

    let proof_dec = general_purpose::STANDARD
        .decode(credential.proof.proof_value)
        .unwrap();

    let proof: PoKOfSignatureG1Proof<Bls12<Config>> =
        CanonicalDeserialize::deserialize_compressed(&proof_dec[..]).unwrap();

    let mut chal_contrib_verifier = vec![];
    proof
        .challenge_contribution(
            &revealed_messages,
            &PARAMS.get().unwrap(),
            &mut chal_contrib_verifier,
        )
        .unwrap();

    let challenge_verifier =
        compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib_verifier);

    proof
        .verify(
            &revealed_messages,
            &challenge_verifier,
            KEY.get().unwrap().0.clone(),
            PARAMS.get().unwrap().clone(),
        )
        .unwrap();

    let client = reqwest::Client::new();
    let body = client
        .post("http://127.0.0.1:8001/check")
        .body(serde_json::to_string(&credential.revocation).unwrap())
        .send()
        .await
        .unwrap();

    if body.status().as_u16() != 200 {
        println!("--------------Revoked--------------")
    }

    return "".to_string();
}

#[get("/credential?<binding>&<offer_id>")]
async fn credential(binding: &str, offer_id: &str) -> (Status, (ContentType, String)) {
    let mut rng = StdRng::seed_from_u64(0u64);

    let map = OFFERS.lock().await;

    let offer = map.get(offer_id).unwrap();

    let mut enc_messages_temp = BTreeMap::new();
    let committed_indices = vec![0].into_iter().collect::<BTreeSet<usize>>();

    let mut index = 1;

    for key in offer.keys().sorted() {
        let msg = format!("{}: {}", key, offer[key]);
        println!("{}", msg);

        let enc_msg = dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<
            Fr,
            Blake2b512,
        >(msg.as_bytes());

        enc_messages_temp.insert(index, enc_msg);
        index += 1;
    }

    let mut uncommitted_messages = BTreeMap::new();
    for (i, msg) in enc_messages_temp.iter().enumerate() {
        uncommitted_messages.insert(i, msg.1);
    }

    let commit_dec = general_purpose::STANDARD
        .decode(binding.to_string())
        .unwrap();

    let commitment = CanonicalDeserialize::deserialize_compressed(&commit_dec[..]).unwrap();

    let uncommitted_messages = (0..4)
        .filter(|i| !committed_indices.contains(i))
        .map(|i| (i, enc_messages_temp.get(&i).unwrap()))
        .collect::<BTreeMap<_, _>>();

    let signature = SignatureG1::<Bls12_381>::new_with_committed_messages(
        &mut rng,
        &commitment,
        uncommitted_messages,
        &KEY.get().unwrap().1,
        &PARAMS.get().unwrap(),
    )
    .unwrap();

    let mut ser = vec![];
    CanonicalSerialize::serialize_compressed(&signature, &mut ser).unwrap();

    let base64 = general_purpose::STANDARD.encode(&ser);

    let client = reqwest::Client::new();
    let body = client
        .post("http://127.0.0.1:8001/add")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let credential_index: u32 = body.parse::<u32>().unwrap();

    let id = Uuid::new_v4();

    let credential = Credential {
        context: vec!["https://www.w3.org/ns/credentials/v2".to_string()],
        credential_type: vec![
            "VerificateCredential".to_string(),
            "TestCredential".to_string(),
        ],
        id: id.to_string(),
        issuer: "http://192.168.1.110:8080".to_string(),
        valid_from: "2023-01-01T00:00:00Z".to_string(),
        credential_subject: json!({ "firstName": "Jonas", "lastName": "Niestroj", "dateOfBirth": "12.07.1999" }),
        proof: CredentialProof {
            created: "2023-01-01T00:00:00Z".to_string(),
            proof_type: "DataIntegrityProof".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: base64,
            verification_method: "".to_string(),
        },
        revocation: Revocation {
            credential_index: credential_index,
            non_revocation_challenge: None,
            non_revocation_proof: None,
        },
    };

    let mut map = CREDENTIALS.lock().await;

    map.insert(id.to_string(), credential.clone());

    (
        Status::Ok,
        (
            ContentType::JSON,
            serde_json::to_string(&credential).unwrap(),
        ),
    )
}

#[post("/revoke")]
fn revoke() -> Status {
    Status::Ok
}

#[get("/params")]
fn params() -> String {
    let mut writer = vec![];
    CanonicalSerialize::serialize_compressed(PARAMS.get().clone().unwrap(), &mut writer).unwrap();

    return general_purpose::STANDARD_NO_PAD.encode(&writer);
}

#[get("/")]
async fn index() -> Template {
    let map = CREDENTIALS.lock().await;

    let credentials = map.values().collect_vec();

    Template::render("index", context! { credentials: credentials })
}

#[launch]
async fn rocket() -> _ {
    let seed = [1, 1, 3, 8, 4, 2];

    let params2 = SignatureParamsG1::new::<Blake2b512>("my seed is cool".as_bytes(), 4);

    let secret_key = SecretKey::generate_using_seed::<Blake2b512>(&seed);
    let public_key = PublicKeyG2::generate_using_secret_key(&secret_key, &params2);

    KEY.set((public_key, secret_key));
    PARAMS.set(params2);

    rocket::build()
        .mount(
            "/",
            routes![verify, sd, offer, credential, presentation, params, index],
        )
        .attach(Template::fairing())
}
