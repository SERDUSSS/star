use ::aes::Aes256;
use encryption::{aes, hash::sha3_256, kyber1024};
use std::{io::{Read, Write}, net::{self, TcpStream}};
use std::mem;
use oqs::kem::{Ciphertext, SharedSecret};

pub mod packets;
pub mod errors;

pub mod encryption {
    pub mod aes;
    pub mod kyber1024;
    pub mod hash;
}

pub struct Handler {
    pub stream: Option<net::TcpStream>,    // TCP stream for communication (Handler)
    pub kem_alg: oqs::kem::Kem,            // Algorithm used
    pub ciphertext: Ciphertext,            // Ciphertext for the encryption local -> peer & back
    pub cipher: Aes256,                    // AES256 encryption key (Handler)
}

impl Handler {
    pub fn new() -> Result<Self, errors::ErrorGeneratingSecureKeys> {
        oqs::init();

        let (kem_alg, pk, sk) = kyber1024::generate_keys()
            .expect("Error generating Kyber1024 keypair");

        let (ciphertext, cipher) = aes::generate_cipher(&kem_alg, &pk, &sk)
            .expect("Error generating AES256 cipher");

        Ok(Handler
            {
                stream: None,
                kem_alg,
                ciphertext,
                cipher,
            })
    }

    
    fn write_kem(&mut self) -> Result<(), errors::WritePKError>
    {
        let cipherlength: &[u8] = &self.ciphertext.as_ref().len().to_ne_bytes();

        self.stream.as_mut().unwrap().write(cipherlength)
            .expect("Couldn't send ciphertext length to peer");

        self.stream.as_mut().unwrap().write(self.ciphertext.as_ref())
            .expect("Couldn't send ciphertext to peer");

        let cipherhash: Vec<u8> = sha3_256(self.ciphertext.as_ref());

        self.stream.as_mut().unwrap().write(&cipherhash)
            .expect("Couldn't send ciphertext hash to peer");

        Ok(())
    }

    fn read_kem(&mut self) -> Result<(), errors::ReadPKError>
    {
        let mut arrkemsize: [u8; mem::size_of::<usize>()] = [0; mem::size_of::<usize>()];

        self.stream.as_mut().unwrap().read_exact(&mut arrkemsize)
            .expect("Couldn't read kem size from peer");

        let kemsize: usize = usize::from_ne_bytes(arrkemsize.try_into()
            .expect("Couldn't convert kemsize from peer &[u8] -> usize"));

        let mut kem: Vec<u8> = vec![0; kemsize];

        self.stream.as_mut().unwrap().read_exact(&mut kem)
            .expect("Couldn't read kem from peer");

        let mut remotearrkemhash: [u8; 32] = [0; 32];

        self.stream.as_mut().unwrap().read_exact(&mut remotearrkemhash)
            .expect("Couldn't read kem hash from peer");

        let remotekemhash: &str = std::str::from_utf8(&remotearrkemhash)
            .expect("Couldn't parse bytes to peer kem hash");

        let arrkemhash: Vec<u8> = sha3_256(&kem);

        let kemhash: &str = std::str::from_utf8(&arrkemhash)
            .expect("Could't parse bytes to hash");

        assert_eq!(remotekemhash, kemhash);

        self.ciphertext = aes::generate_cipher_from_vec(&self.kem_alg, kem, &self.ciphertext).unwrap();
        
        Ok(())
    }
    
    pub fn connect(&mut self, host: String) -> Result<(), errors::HandShakeError>
    {
        let stream = TcpStream::connect(host)
            .expect("Could not connect to peer");

        self.stream = Some(stream);

        self.write_kem()
            .expect("Couldn't create secure channel with peer (OQS KEM Kyber1024)");

        Ok(())
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), errors::ErrorSendingData>
    {
        let ebuf: &[u8] = &aes::encrypt(&self.cipher, buf).unwrap();

        let buflength: &[u8] = &ebuf.len().to_ne_bytes();

        let bufhash: &[u8] = &sha3_256(ebuf);

        self.stream.as_mut().unwrap().write_all(buflength)
            .expect("Could not send bugger length to peer");

        self.stream.as_mut().unwrap().write_all(ebuf)
            .expect("Could not send buffer to peer");

        self.stream.as_mut().unwrap().write_all(bufhash)
            .expect("Could not send buffer hash to peer");

        // println!("{}", String::from_utf8(aes::decrypt(&self.cipher, ebuf).unwrap()).unwrap());

        Ok(())
    }

    pub fn read(&mut self) -> Result<Vec<u8>, errors::ErrorReceivingData>
    {
        let mut arrbufsize: [u8; mem::size_of::<usize>()] = [0; mem::size_of::<usize>()];

        self.stream.as_mut().unwrap().read_exact(&mut arrbufsize)
            .expect("Couldn't read buffer size from peer");

        let bufsize: usize = usize::from_ne_bytes(arrbufsize.try_into()
            .expect("Couldn't convert bufsize from peer &[u8] -> usize"));

        let mut buf: Vec<u8> = vec![0; bufsize];

        self.stream.as_mut().unwrap().read_exact(&mut buf)
            .expect("Couldn't read buffer from peer");

        let mut remotearrbufhash: [u8; 32] = [0; 32];

        self.stream.as_mut().unwrap().read_exact(&mut remotearrbufhash)
            .expect("Couldn't read buffer hash from peer");

        let remotebufhash: &str = std::str::from_utf8(&remotearrbufhash)
            .expect("Couldn't parse bytes to peer buffer hash");

        let arrbufhash: Vec<u8> = sha3_256(&buf);

        let bufhash: &str = std::str::from_utf8(&arrbufhash)
            .expect("Could't parse bytes to hash");

        assert_eq!(remotebufhash, bufhash);

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use oqs::Error;

    use super::*;

    #[test]
    fn test_connect() -> Result<(), Error> {
        let mut client = Handler::new()
            .expect("Could not create object");

        client.connect("127.0.0.1:8001".to_owned())
            .expect("Could not stablish a connection with peer");

        let buf: &[u8] = &[0; 1000];

        client.write(buf)
            .expect("Error test");

        Ok(())
    }
}
