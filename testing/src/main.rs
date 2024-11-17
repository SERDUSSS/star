use oqs::kem::{Kem, SecretKey, Ciphertext, SharedSecret};
use aes::{Aes256, BlockCipher};
use block_modes::{BlockMode, Cbc};
use block_padding::Pkcs7;
use rand::{Rng, thread_rng};
use std::convert::TryInto;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// Phase 1: Key Exchange (Kyber1024)
fn key_exchange(kem: &Kem) -> Result<(Vec<u8>, SharedSecret), Box<dyn std::error::Error>> {
    // Server generates a key pair (public and private keys)
    let (server_public_key, server_secret_key) = kem.keypair()?;

    // Client encapsulates a shared secret with the server's public key
    let (ciphertext, client_shared_secret) = kem.encapsulate(&server_public_key)?;

    // Serialize the ciphertext to Vec<u8> to simulate transmission
    let ciphertext_bytes = ciphertext.into_vec();

    Ok((ciphertext_bytes, client_shared_secret))
}

/// Encrypt data using AES256-CBC with PKCS7 padding
fn encrypt_data(aes_key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // Generate a random IV (Initialization Vector)
    let iv: Vec<u8> = (0..16).map(|_| thread_rng().gen()).collect(); // 16 bytes IV

    // Create AES256 cipher in CBC mode with PKCS7 padding
    let cipher = Aes256Cbc::new_from_slices(aes_key, &iv).expect("AES cipher creation failed");

    // Encrypt the data
    let ciphertext_aes = cipher.encrypt_vec(plaintext);

    Ok((iv, ciphertext_aes))
}

/// Decrypt data using AES256-CBC with PKCS7 padding
fn decrypt_data(aes_key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create AES256 cipher in CBC mode with PKCS7 padding for decryption
    let cipher = Aes256Cbc::new_from_slices(aes_key, iv).expect("AES cipher creation failed");

    // Decrypt the data
    let decrypted_data = cipher.decrypt_vec(ciphertext)?;

    Ok(decrypted_data)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize Kyber1024 KEM
    let kem = Kem::new(oqs::kem::Algorithm::Kyber1024)?;

    // Phase 1: Key Exchange
    let (ciphertext_bytes, client_shared_secret) = key_exchange(&kem)?;
    println!("Client shared secret: {:?}", client_shared_secret);

    // Simulate transmission of ciphertext (using the shared secret to derive AES key)
    let server_shared_secret = kem.decapsulate(&Ciphertext::from_bytes(&ciphertext_bytes)?, &kem.keypair()?.1)?;

    // Phase 2: Encrypt data using AES256 (derived from Kyber1024 shared secret)
    let aes_key = &server_shared_secret.into_vec()[..32]; // Use the first 32 bytes of the shared secret as the AES key
    let plaintext = b"Hello, this is a secret message!";
    let (iv, ciphertext_aes) = encrypt_data(aes_key, plaintext)?;

    println!("Encrypted message: {:?}", ciphertext_aes);

    // Phase 3: Decrypt data using AES256 (derived from the same shared secret)
    let decrypted_data = decrypt_data(aes_key, &iv, &ciphertext_aes)?;

    println!("Decrypted message: {:?}", String::from_utf8(decrypted_data)?);

    // Verify the decrypted message matches the original plaintext
    assert_eq!(plaintext.to_vec(), decrypted_data);
    println!("Decryption successful! The message was correctly decrypted.");

    Ok(())
}

