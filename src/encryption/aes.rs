use aes::{Aes256, NewBlockCipher};
use ctr::cipher::{NewCipher, StreamCipher};
use oqs::kem::{Kem, PublicKey, SecretKey, Ciphertext, SharedSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use generic_array::GenericArray;
use sha2::digest::consts::U12;
use rand::RngCore;
use anyhow::Result;
use ctr::Ctr128BE;



pub type Aes256Ctr = Ctr128BE<Aes256>; // Define AES-CTR type using AES-256

pub fn generate_cipher(
    kem_alg: &Kem,
    pka: &PublicKey,
    ska: &SecretKey,
) -> Result<(Ciphertext, Aes256Ctr), Box<dyn std::error::Error>> {
    // Encapsulate to get the ciphertext and shared secret
    let (ciphertext, shared_secret) = kem_alg.encapsulate(pka)?;

    // Decapsulate to verify the shared secret
    let shared_secret_b: SharedSecret = kem_alg.decapsulate(ska, &ciphertext)?;
    assert_eq!(shared_secret, shared_secret_b);

    // Derive a 256-bit AES key using HKDF and the shared secret
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
    let mut okm: [u8; 32] = [0u8; 32]; // 32 bytes for AES-256 key
    hk.expand(b"", &mut okm).expect("HKDF expand failed");

    // Create an AES-CTR cipher using the derived key
    let aes_key: GenericArray<u8, _> = GenericArray::clone_from_slice(&okm);
    let nonce = GenericArray::from_slice(&[0u8; 16]); // 16-byte nonce for AES-CTR
    let cipher = Aes256Ctr::new(&aes_key, nonce);

    Ok((ciphertext, cipher))
}


pub fn generate_nonce() -> Result<GenericArray<u8, U12>>
{

    let mut nonce_bytes: [u8; 12] = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce: GenericArray<u8, U12> = *Nonce::from_slice(&nonce_bytes);

    Ok(nonce)
}
