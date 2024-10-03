use thiserror::Error;
use generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use oqs::kem::{Ciphertext, Kem, PublicKey, SecretKey, SharedSecret};

const CHUNK_SIZE: usize = 16;

#[derive(Error, Debug)]
pub enum EncryptError {
    #[error("Encryption error")]
    EncryptionError,
}

#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("Decryption error")]
    DecryptionError,
}

pub fn generate_cipher(
    kem_alg: &Kem,
    pka: &PublicKey,
    ska: &SecretKey,
) -> Result<(Ciphertext, Aes256), oqs::Error> {
    let (ciphertext, shared_secret) = kem_alg.encapsulate(pka)?;

    let shared_secret_b: SharedSecret = kem_alg.decapsulate(ska, &ciphertext)?;

    assert_eq!(shared_secret, shared_secret_b);

    let aes_key: GenericArray<u8, _> = GenericArray::clone_from_slice(&shared_secret.as_ref()[..32]);

    let cipher: Aes256 = Aes256::new(&aes_key);

    Ok((ciphertext, cipher))
}

pub fn encrypt(cipher: &Aes256, text: &[u8]) -> Result<Vec<u8>, EncryptError> {

    if text.len() % CHUNK_SIZE != 0 {
        return Err(EncryptError::EncryptionError);
    }

    let mut encrypted_data = Vec::with_capacity(text.len());

    for chunk in text.chunks(CHUNK_SIZE) {

        let mut block = GenericArray::clone_from_slice(chunk); // Create a mutable copy
        cipher.encrypt_block(&mut block);
        encrypted_data.extend_from_slice(&block);
    }

    Ok(encrypted_data)
}

pub fn decrypt(cipher: &Aes256, text: &[u8]) -> Result<Vec<u8>, DecryptError> {

    if text.len() % CHUNK_SIZE != 0 {
        return Err(DecryptError::DecryptionError);
    }

    let mut decrypted_data = Vec::with_capacity(text.len());

    for chunk in text.chunks(CHUNK_SIZE) {

        let mut block = GenericArray::clone_from_slice(chunk); // Create a mutable copy
        cipher.decrypt_block(&mut block);
        decrypted_data.extend_from_slice(&block);
    }

    Ok(decrypted_data)
}