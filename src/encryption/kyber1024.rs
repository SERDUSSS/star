use oqs::kem::{self, SharedSecret};
use oqs::kem::Kem;
use oqs::Result;

pub fn generate_keys(kem: Kem) -> Result<(kem::Kem, oqs::kem::PublicKey, oqs::kem::SecretKey)>
{
    let (pka, ska) = kem.keypair()?;

    let (ct, sc) = kem.encapsulate(&pka)?;

    let scb: SharedSecret = kem.decapsulate(&ska, &ct)?;

    Ok((kem, pka, ska))
}
