use generic_array::GenericArray;
use aes::cipher::KeyInit;
use aes::Aes256;
use oqs::{kem::{Ciphertext, Kem, PublicKey, SecretKey, SharedSecret}, Error};

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

pub fn encrypt(cipher: &Aes256, text: &[u8]) -> Result<Vec<u8>, Error>
{
    Ok(vec![])
}

pub fn decrypt(cipher: &Aes256, text: &[u8]) -> Result<Vec<u8>, Error>
{
    Ok(vec![])
}