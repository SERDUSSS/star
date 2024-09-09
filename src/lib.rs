use aes_gcm::Aes256Gcm;
use aes_gcm::aead::Aead;
use aes_gcm::aead::generic_array::GenericArray;
use encryption::{aes, kyber1024};
use sha2::digest::consts::U12;
use anyhow::Result;
use std::{io::Write, net::{self, TcpListener, TcpStream}};

// MAX SIZE CAPABLE OF SENDING PER PACKET: 20753296360 Bytes (19.328014351 GB)
// MAX REDIRECTABLE SIZE: 1360067276952600 Bytes (1.360067276952600102 PB)

pub mod packets {
    pub mod conn;
    pub mod kem;
    pub mod normal;
    pub mod resend;
    pub mod reverse;
}

pub mod encryption {
    pub mod aes;
    pub mod kyber1024;
    pub mod hash;
}

pub mod packet_handler;
pub mod sockets;
pub mod status;

pub struct Client
{
    host: String,
    port: u16,
    stream: Option<net::TcpStream>,
    kem_alg: oqs::kem::Kem,
    pka: oqs::kem::PublicKey,
    ska: oqs::kem::SecretKey,
    pkb: oqs::kem::PublicKey,
    ciphertext: oqs::kem::Ciphertext,
    cipher: Aes256Gcm,
    nonce: GenericArray<u8, U12>
}

impl Client
{

    pub fn new() -> Result<Self>
    {
        oqs::init();

        let host: String = "0.0.0.0".to_owned(); 

        let port: u16 = 65535;

        let (kem_alg, pka, ska) = kyber1024::generate_keys()
            .expect("Error generating keypair");

        let pkb = pka.clone();

        let (ciphertext, cipher) = aes::generate_cipher(&kem_alg, &pka, &ska)
            .expect("Error generating cipher");

        let nonce = aes::generate_nonce()
            .expect("Error generating nonce");

        Ok(Client 
            {
                host,
                port,
                stream: None,
                kem_alg,
                pka,
                ska,
                pkb,
                ciphertext,
                cipher,
                nonce
            })
    }

    fn get_stream(&mut self) -> &TcpStream
    {
        let stream: &TcpStream = &self.stream.as_ref().unwrap();
        stream
    }

    fn encrypt(&mut self, data: &str) -> Result<Vec<u8>>
    {
        let plaintext: &[u8] = data.as_bytes();

        let encrypted_data: Vec<u8> = self.cipher.encrypt(&self.nonce, plaintext.as_ref())
            .expect("Encryption failed");
        
        Ok(encrypted_data)
    }

    fn decrypt(&mut self, data: Vec<u8>) -> Result<String>
    {
        let decrypted_bytes: Vec<u8> = self.cipher.decrypt(&self.nonce, data.as_ref())
            .expect("Decryption failed");

        let decrypted_data = String::from_utf8(decrypted_bytes)
            .expect("Could not parse to utf-8");
        
        Ok(decrypted_data)
    }

    pub fn connect(&mut self, host: String, port: u16) -> Result<()>
    {
        match net::TcpStream::connect(format!("{}:{}", host, port)) {
            Ok(stream) => 
            {
                let stream: TcpStream = stream;
                println!("Connected!");
                self.stream = Some(stream);
                self.host = host;
                self.port = port;
            } Err(e) => {
                eprintln!("Failed to connect: {}", e);
            }
        };

        Ok(())
    }

    pub fn write(&mut self,  data: Vec<u8>) -> Result<()>
    {
        let mut stream: &TcpStream = self.get_stream();

        let data: &[u8] = &data;

        stream.write_all(data)
            .expect("error");

        Ok(())
    }

    pub fn send(&mut self, data: &str) -> Result<()>
    {
        // Generate new nonce (Will generate different data with the same key)
        self.nonce = encryption::aes::generate_nonce()?;

        ////////////////////////////////////////////////////////////////////////////////////////
        // Encrypt the data with our public key?
        let encrypted_data = self.encrypt(data)
            .expect("Error encrypting data");

        println!("{:?}", encrypted_data);


        /////////////////////////////////////////////////////////////////////////////////////////
        // Send the data over a socket packet
        self.write(encrypted_data)
            .expect("Error sending data");

        Ok(())
    }

    pub fn receive(&mut self) -> Result<[u8; 64000]>
    {
        // Receive encrypted_text

        //let decrypted_bytes: Vec<u8> = self.cipher.decrypt(&self.nonce, encrypted_text.as_ref())
        //    .expect("Decryption failed");

        //let decrypted_message: String = String::from_utf8(decrypted_bytes)
        //    .expect("Failed to convert bytes to string");

        // Ok(decrypted_message)

        Ok([0u8;64000])
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Import everything from the parent module

    #[test]
    fn test_connect() {
        let mut client = Client::new()
            .expect("Could not create");

        // Call the connect function
        client.connect("127.0.0.1".to_owned(), 8000 as u16)
            .expect("Could not stablish a connection");

        client.send("hola mundo!, hola mundo!")
            .expect("Could not send the data");

        client.send("hola mundo!")
            .expect("Could not send the data");
    }
}