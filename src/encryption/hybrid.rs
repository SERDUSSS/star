use oqs::kem::{Kem, SecretKey, Ciphertext};
use aes::{Aes256, BlockCipher};
use block_modes::{BlockMode, Cbc};
use block_padding::Pkcs7;
use rand::{Rng, thread_rng};
use std::convert::TryInto;


/// Phase 1: Key Exchange (Kyber1024)
fn key_exchange(kem: &Kem) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // Server generates a key pair (public and private keys)
    let (server_public_key, server_secret_key) = kem.keypair()?;

    // Client encapsulates a shared secret with the server's public key
    let (ciphertext, client_shared_secret) = kem.encapsulate(&server_public_key)?;

    // Serialize the ciphertext to Vec<u8> to simulate transmission
    let ciphertext_bytes: Vec<u8> = ciphertext.bytes().to_vec();

    Ok((ciphertext_bytes, client_shared_secret))
}

/// Phase 2: Encrypt the data using AES256
fn encrypt_data(aes_key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // Generate a random IV (Initialization Vector)
    let iv: Vec<u8> = (0..16).map(|_| thread_rng().gen()).collect(); // 16 bytes IV

    // Create AES256 cipher in CBC mode with PKCS7 padding
    let cipher = Aes256Cbc::new_var(aes_key, &iv).expect("AES cipher creation failed");

    // Encrypt the data
    let ciphertext_aes: Vec<u8> = cipher.encrypt_vec(plaintext);

    Ok((iv, ciphertext_aes))
}

/// Phase 3: Decrypt the data using AES256
fn decrypt_data(aes_key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create AES256 cipher in CBC mode with PKCS7 padding for decryption
    let cipher = Aes256Cbc::new_var(aes_key, iv).expect("AES cipher creation failed");

    // Decrypt the data
    let decrypted_data: Vec<u8> = cipher.decrypt_vec(ciphertext)?;

    Ok(decrypted_data)
}
