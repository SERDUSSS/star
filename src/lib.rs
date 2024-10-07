use ::aes::Aes256;
use encryption::{aes, kyber1024, hash};
use std::{io::{Read, Write}, net::{self, TcpStream}};
use std::mem;

pub mod packets;
pub mod errors;

pub mod encryption {
    pub mod aes;
    pub mod kyber1024;
    pub mod hash;
}

pub struct Client {
    pub host: String,                      // The remote host
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

        let (kem_alg, pk, sk) = kyber1024::generate_keys()
            .expect("Error generating Kyber1024 keypair");

        let (ciphertext, cipher) = aes::generate_cipher(&kem_alg, &pk, &sk)
            .expect("Error generating AES256 cipher");

        Ok(Client
            {
                host,
                stream: None,
                kem_alg,
                pk,
                ciphertext,
                cipher,
            })
    }

    
    fn kem(&mut self) -> Result<(), errors::SendPKError>
    {
        Ok(())
    }

    pub fn connect(&mut self, host: String) -> Result<(), errors::HandShakeError>
    {
        let stream = TcpStream::connect(host)
            .expect("Could not connect to remote host");

        self.stream = Some(stream);

        self.kem();

        Ok(())
    }

    pub fn send(&mut self, buf: &[u8]) -> Result<(), errors::ErrorSendingData>
    {
        let ebuf: &[u8] = &aes::encrypt(&self.cipher, buf).unwrap();

        let buflength: &[u8] = &ebuf.len().to_ne_bytes();

        let bufhash: &[u8] = &hash::sha3_256(ebuf);

        self.stream.as_mut().unwrap().write_all(buflength)
            .expect("Could not send data length");

        self.stream.as_mut().unwrap().write_all(ebuf)
            .expect("Could not send data");

        self.stream.as_mut().unwrap().write_all(bufhash)
            .expect("Could not send hash");

        // send hash

        // println!("{}", String::from_utf8(aes::decrypt(&self.cipher, ebuf).unwrap()).unwrap());

        Ok(())
    }

    pub fn receive(&mut self) -> Result<Vec<u8>, errors::ErrorReceivingData>
    {
        let mut arrbufsize: [u8; mem::size_of::<usize>()] = [0; mem::size_of::<usize>()];

        self.stream.as_mut().unwrap().read_exact(&mut arrbufsize)
            .expect("Error couldn't read buffer size");

        let bufsize: usize = usize::from_ne_bytes(arrbufsize.try_into()
            .expect("Error conversing bufsize &[u8] -> usize"));

        let mut buf: Vec<u8> = vec![0; bufsize];

        self.stream.as_mut().unwrap().read_exact(&mut buf)
            .expect("Could not read buffer");

        let mut arrbufhash: [u8; 32] = [0; 32];

        self.stream.as_mut().unwrap().read_exact(&mut arrbufhash)
            .expect("Error couldn't read buffer hash");

        let bufhash = std::str::from_utf8(&arrbufhash)
            .expect("Couldn't parse bytes to hash");


        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use oqs::Error;

    use super::*; // Import everything from the parent module

    #[test]
    fn test_connect() -> Result<(), Error> {
        let mut client = Client::new()
            .expect("Could not create");

        client.connect("127.0.0.1:8001".to_owned())
            .expect("Could not stablish a connection");

        let buf: &[u8] = &[0; 1000];

        client.send(buf)
            .expect("Error test");

        Ok(())
    }
}
