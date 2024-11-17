use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use oqs::kem::{Kem, SharedSecret};
use rand::{Rng, thread_rng};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// Key Exchange (Kyber1024)
pub fn key_exchange(kem: &Kem) -> Result<(Vec<u8>, SharedSecret), Box<dyn std::error::Error>> {
    // Server generates a key pair (public and private keys)
    let (server_public_key, _server_secret_key) = kem.keypair()?;

    // Client encapsulates a shared secret with the server's public key
    let (ciphertext, client_shared_secret) = kem.encapsulate(&server_public_key)?;

    // Serialize the ciphertext to Vec<u8> to simulate transmission
    let ciphertext_bytes: Vec<u8> = ciphertext.into_vec();

    Ok((ciphertext_bytes, client_shared_secret))
}

/// Encrypt data using AES256-CBC with PKCS7 padding
pub fn encrypt_data(aes_key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // Generate a random IV (Initialization Vector)
    let iv: Vec<u8> = (0..16).map(|_| thread_rng().gen()).collect(); // 16 bytes IV

    // Create AES256 cipher in CBC mode with PKCS7 padding
    let cipher: Cbc<Aes256, Pkcs7> = Aes256Cbc::new_from_slices(aes_key, &iv).expect("AES cipher creation failed");

    // Encrypt the data
    let ciphertext_aes: Vec<u8> = cipher.encrypt_vec(plaintext);

    Ok((iv, ciphertext_aes))
}

/// Decrypt data using AES256-CBC with PKCS7 padding
pub fn decrypt_data(aes_key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create AES256 cipher in CBC mode with PKCS7 padding for decryption
    let cipher: Cbc<Aes256, Pkcs7> = Aes256Cbc::new_from_slices(aes_key, iv).expect("AES cipher creation failed");

    // Decrypt the data
    let decrypted_data: Vec<u8> = cipher.decrypt_vec(ciphertext)?;

    Ok(decrypted_data)
}
