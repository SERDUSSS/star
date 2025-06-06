use ::aes::Aes256;
use encryption::{hash, hybrid};
use std::{io::{Read, Write}, net::{self, TcpStream}};
use std::mem;
use oqs::kem::{Ciphertext, Kem, SharedSecret};

pub mod packets;
pub mod errors;

pub mod encryption {
    pub mod hybrid;
    pub mod hash;
}

pub struct Handler {
    pub stream: Option<net::TcpStream>,    // TCP stream for communication (Handler)
    pub kem: oqs::kem::Kem,                // Algorithm used
    pub ct: Vec<u8>,                       // Ciphertext for the encryption local -> peer & back
    pub sc: SharedSecret,                  // Shared Secret (KEY)
}

impl Handler {
    pub fn new() -> Result<Self, errors::ErrorGeneratingSecureKeys> {
        oqs::init();

        let kem: Kem = Kem::new(oqs::kem::Algorithm::Kyber1024).unwrap();

        let (ct, sc) = hybrid::key_exchange(&kem).unwrap();

        Ok(Handler
            {
                stream: None,
                kem,
                ct,
                sc,
            })
    }

    fn send_key(&mut self) -> Result<(), errors::WritePKError>
    {
        let cipherlength: &[u8] = &self.ct.len().to_ne_bytes();

        self.stream.as_mut().unwrap().write(cipherlength)
            .expect("Couldn't send ciphertext length to peer");

        self.stream.as_mut().unwrap().write(self.ct.as_ref())
            .expect("Couldn't send ciphertext to peer");

        let cipherhash: Vec<u8> = hash::sha3_256(self.ct.as_ref());

        self.stream.as_mut().unwrap().write(&cipherhash)
            .expect("Couldn't send ciphertext hash to peer");

        Ok(())
    }

    fn read_key(&mut self) -> Result<(), errors::ReadPKError>
    {
        let mut arrkeysize: [u8; mem::size_of::<usize>()] = [0; mem::size_of::<usize>()];

        self.stream.as_mut().unwrap().read_exact(&mut arrkeysize)
            .expect("Couldn't read key size from peer");

        let keysize: usize = usize::from_ne_bytes(arrkeysize.try_into()
            .expect("Couldn't convert keysize from peer &[u8] -> usize"));

        let mut key: Vec<u8> = vec![0; keysize];

        self.stream.as_mut().unwrap().read_exact(&mut key)
            .expect("Couldn't read key from peer");

        let mut remotearrkeyhash: [u8; 32] = [0; 32];

        self.stream.as_mut().unwrap().read_exact(&mut remotearrkeyhash)
            .expect("Couldn't read key hash from peer");

        let remotekeyhash: &str = std::str::from_utf8(&remotearrkeyhash)
            .expect("Couldn't parse bytes to peer key hash");

        let arrkeyhash: Vec<u8> = hash::sha3_256(&key);

        let keyhash: &str = std::str::from_utf8(&arrkeyhash)
            .expect("Could't parse bytes to hash");

        assert_eq!(remotekeyhash, keyhash);

        let ciphertext = Ciphertext::new(key)?;

        self.kem.decapsulate(&Ciphertext::from_bytes(&key)?, &self.kem.keypair().unwrap().1)?;
        
        Ok(())
    }
    
    pub fn connect(&mut self, host: String) -> Result<(), errors::HandShakeError>
    {
        let stream = TcpStream::connect(host)
            .expect("Could not connect to peer");

        self.stream = Some(stream);

        self.send_key()
            .expect("Couldn't create secure channel with peer (OQS KEM Kyber1024)");

        Ok(())
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), errors::ErrorSendingData>
    {
        let ebuf: &[u8] = &aes::encrypt(&self.cipher, buf).unwrap();

        let buflength: &[u8] = &ebuf.len().to_ne_bytes();

        let bufhash: &[u8] = &hash::sha3_256(ebuf);

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

        let arrbufhash: Vec<u8> = hash::sha3_256(&buf);

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
