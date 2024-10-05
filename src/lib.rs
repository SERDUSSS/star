use ::aes::Aes256;
use encryption::{aes, kyber1024, hash};
use std::net;
pub mod packets;
pub mod errors;

pub mod encryption {
    pub mod aes;
    pub mod kyber1024;
    pub mod hash;
}

pub struct Client {
    pub host: String,                      // The remote host
    pub port: u16,                         // The remote port
    pub stream: Option<net::TcpStream>,    // TCP stream for communication
    pub kem_alg: oqs::kem::Kem,            // The KEM algorithm used, Kyber1024
    pub pk: oqs::kem::PublicKey,           // Public key for post-quantum encryption
    pub ciphertext: oqs::kem::Ciphertext,  // Ciphertext for the encryption
    pub cipher: Aes256,                    // AES256 encryption key
}

impl Client {
    pub fn new() -> Result<Self, errors::ErrorGeneratingSecureKeys> {
        oqs::init();

        let host: String = "0.0.0.0".to_owned();
        let port: u16 = 65535;

        let (kem_alg, pk, sk) = kyber1024::generate_keys()
            .expect("Error generating Kyber1024 keypair");

        let (ciphertext, cipher) = aes::generate_cipher(&kem_alg, &pk, &sk)
            .expect("Error generating AES256 cipher");

        Ok(Client
            {
                host,
                port,
                stream: None,
                kem_alg,
                pk,
                ciphertext,
                cipher,
            })
    }

    
    fn send_pk(&mut self) -> Result<(), errors::SendPKError>
    {
        Ok(())
    }

    pub fn connect(&mut self, host: String, port: u16) -> Result<(), errors::HandShakeError>
    {
        Ok(())
    }

    pub fn send(&mut self, data: &str) -> Result<(), errors::ErrorSendingData>
    {
        Ok(())
    }

    pub fn receive(&mut self) -> Result<[u8; 64000], errors::ErrorReceivingData>
    {
        Ok(())
    }
}

/*#[cfg(test)]
mod tests {
    use super::*; // Import everything from the parent module

    #[test]
    fn test_connect() {
        let mut client = Client::new()
            .expect("Could not create");

        // Call the connect function
        client.connect("127.0.0.1".to_owned(), 8000 as u16)
            .expect("Could not stablish a connection");

        let x = client.encrypt_tagless("asd")
            .expect("Error");

        let y = client.decrypt_tagless(x)
            .expect("Error2");

        println!("{}", y);
    }
}*/
