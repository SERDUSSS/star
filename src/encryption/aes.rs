use generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use oqs::kem::{Ciphertext, Kem, PublicKey, SecretKey, SharedSecret};

use crate::errors;

const CHUNK_SIZE: usize = 16;

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

pub fn encrypt(cipher: &Aes256, text: &[u8]) -> Result<Vec<u8>, errors::EncryptError> {

    let padded_text: Vec<u8> = pad(text, CHUNK_SIZE);
    
    let mut encrypted_data: Vec<u8> = Vec::with_capacity(padded_text.len());

    for chunk in padded_text.chunks(CHUNK_SIZE) {
        let mut block: GenericArray<u8, _> = GenericArray::clone_from_slice(chunk); // Now chunk size will always be 16
        cipher.encrypt_block(&mut block);
        encrypted_data.extend_from_slice(&block);
    }
    
    Ok(encrypted_data)
}

fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut padded_data = Vec::with_capacity(data.len() + padding_len);
    padded_data.extend_from_slice(data);
    padded_data.extend(vec![padding_len as u8; padding_len]);
    padded_data
}

pub fn decrypt(cipher: &Aes256, encrypted_data: &[u8]) -> Result<Vec<u8>, errors::DecryptError> {

    if encrypted_data.len() % CHUNK_SIZE != 0 {
        return Err(errors::DecryptError::DecryptionError);
    }
    
    let mut decrypted_data = Vec::with_capacity(encrypted_data.len());

    for chunk in encrypted_data.chunks(CHUNK_SIZE) {
        let mut block = GenericArray::clone_from_slice(chunk); // The chunk size will always be 16
        cipher.decrypt_block(&mut block);
        decrypted_data.extend_from_slice(&block);
    }

    unpad(&mut decrypted_data).map_err(|_| errors::DecryptError::DecryptionError)?;

    Ok(decrypted_data)
}

fn unpad(data: &mut Vec<u8>) -> Result<(), ()> {
    if let Some(&pad_byte) = data.last() {
        let pad_len = pad_byte as usize;
        if pad_len == 0 || pad_len > CHUNK_SIZE || pad_len > data.len() {
            return Err(()); // Invalid padding
        }
        // Check that the padding bytes are valid
        if data[data.len() - pad_len..].iter().all(|&byte| byte == pad_byte) {
            data.truncate(data.len() - pad_len); // Remove padding
            Ok(())
        } else {
            Err(()) // Invalid padding bytes
        }
    } else {
        Err(()) // Data is empty, can't unpad
    }
}