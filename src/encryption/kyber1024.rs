use oqs::kem;
use oqs::Result;

pub fn generate_keys() -> Result<(kem::Kem, oqs::kem::PublicKey, oqs::kem::SecretKey)>
{
    let kem_alg: kem::Kem = kem::Kem::new(kem::Algorithm::Kyber1024)?;

    let (pka, ska) = kem_alg.keypair()?;

    Ok((kem_alg, pka, ska))
}
