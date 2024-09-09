use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::KeyInit;
use aes_gcm::aead::generic_array::GenericArray;
use hkdf::Hkdf;
use sha2::digest::consts::U12;
use sha2::Sha256;
use rand::RngCore;
use anyhow::Result;

pub fn generate_cipher(
    kem_alg: &oqs::kem::Kem,
    pka: &oqs::kem::PublicKey,
    ska: &oqs::kem::SecretKey,
) -> Result<(oqs::kem::Ciphertext, Aes256Gcm)>
{
    let (ciphertext, shared_secret) = kem_alg.encapsulate(pka)?;

    let shared_secret_b: oqs::kem::SharedSecret = kem_alg.decapsulate(ska, &ciphertext)?;

    assert_eq!(shared_secret, shared_secret_b);

    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
    let mut okm: [u8; 32] = [0u8; 32]; // 32 bytes for AES-256 key
    hk.expand(b"", &mut okm).expect("HKDF expand failed");

    let aes_key: GenericArray<u8, _> = GenericArray::clone_from_slice(&okm);
    let cipher = Aes256Gcm::new(&aes_key);

    Ok((ciphertext, cipher))
}

pub fn generate_nonce() -> Result<GenericArray<u8, U12>>
{

    let mut nonce_bytes: [u8; 12] = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce: GenericArray<u8, U12> = *Nonce::from_slice(&nonce_bytes);

    Ok(nonce)
}
