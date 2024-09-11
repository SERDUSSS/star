use aes_gcm::Aes256Gcm;
use aes_gcm::aead::Aead;
use aes_gcm::aead::generic_array::GenericArray;
use encryption::{aes, hash::sha3_256, kyber1024};
use oqs::kem::PublicKey;
use sha2::digest::consts::U12;
use anyhow::Result;
use std::{io::Write, net::{self, TcpListener, TcpStream}};

// MAX SIZE CAPABLE OF SENDING PER PACKET: 20753296360 Bytes (19.328014351 GB)
// MAX REDIRECTABLE SIZE: 1360067276952600 Bytes (1.360067276952600102 PB)

const CHUNK_SIZE: usize = 1 * 1024 * 1024 * 1024; // 1 GB

pub mod encryption {
    pub mod aes;
    pub mod kyber1024;
    pub mod hash;
}

pub mod packets;
pub mod packet_handler;

pub struct Client
{
    host: String,
    port: u16,
    stream: Option<net::TcpStream>,
    kem_alg: oqs::kem::Kem,
    pk: oqs::kem::PublicKey,
    sk: oqs::kem::SecretKey,
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

        let (kem_alg, pk, sk) = kyber1024::generate_keys()
            .expect("Error generating keypair");

        let (ciphertext, cipher) = aes::generate_cipher(&kem_alg, &pk, &sk)
            .expect("Error generating cipher");

        let nonce = aes::generate_nonce()
            .expect("Error generating nonce");

        Ok(Client 
            {
                host,
                port,
                stream: None,
                kem_alg,
                pk,
                sk,
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

    fn get_pk(&mut self) -> &PublicKey
    {
        let pk: &PublicKey = &self.pk;
        pk
    }

    fn encrypt(&mut self, data: &str) -> Result<Vec<u8>>
    {
        let plaintext: &[u8] = data.as_bytes();

        let encrypted_data: Vec<u8> = self.cipher.encrypt(&self.nonce, plaintext.as_ref())
            .expect("Encryption failed");
        
        Ok(encrypted_data)
    }

    fn decrypt(&mut self, data: &Vec<u8>) -> Result<String>
    {
        let decrypted_bytes: Vec<u8> = self.cipher.decrypt(&self.nonce, data.as_ref())
            .expect("Decryption failed");

        let decrypted_data = String::from_utf8(decrypted_bytes)
            .expect("Could not parse to utf-8");
        
        Ok(decrypted_data)
    }

    fn send_pk(&mut self) -> Result<()>
    {

        let pk: &PublicKey = &self.get_pk().clone();
        let pk: &[u8] = pk.as_ref();
        
        let mut stream: &TcpStream = self.get_stream();
        
        let key_size = (pk.len() + (256 / 8)) as u32;

        let hash: &[u8] = &sha3_256(pk.to_vec());

        println!("{}", key_size);
        println!("{:?}", pk);

        stream.write_all(&key_size.to_be_bytes())?;

        stream.write_all(pk)?;

        stream.write_all(hash)?;

        Ok(())
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
                self.send_pk()?;
                //self.send_challenge();
                //self.read_challenge();
                // VERIFY CHALLENGE
                //self.send_shared_secret();
                //self.send_aes_challenge();
                //self.read_aes_challenge();
                // VERIFY AES CHALLENGE
            } Err(e) => {
                eprintln!("Failed to connect: {}", e);
            }
        };

        Ok(())
    }

    pub fn send(&mut self, data: &str) -> Result<()>
    {
        // Generate new nonce
        let nonce: GenericArray<u8, U12> = encryption::aes::generate_nonce()?;
        self.nonce = nonce;

        // Encrypt the data with our shared secret
        let encrypted_data: Vec<u8> = self.encrypt(data)
            .expect("Error encrypting data");

        println!("{}", data);

        let mut stream: &TcpStream = self.get_stream();

        /*let data: &[u8] = &vec![42; 11000000000];

        stream.write_all(data)?;
        stream.write_all(data)?;*/

        let data: &[u8] = &data;
        
        //     Req Type (1 byte) + Keep_alive (1 byte) + Nonce length (12 bytes)
        //     All data (Unknown) + SHA3-256 (32 bytes)
        let size: u64 = (1 + 1 + 12 + data.len() + 32) as u64;
        
        let hash: &[u8] = &sha3_256(data.to_vec());

        let packet: packets::Stream = packets::Stream {
            length: &size.to_be_bytes(),
            req_type: 1,
            keep_alive: true,
            nonce: nonce,
            data: data,
            hash: hash,
        };

        stream.write_all(bincode::serialize(&packet))?;

        Ok(())
    }

    pub fn send_file(&mut self, file: &str) -> Result<()>
    {
        // Generate new nonce
        let nonce: GenericArray<u8, U12> = encryption::aes::generate_nonce()?;
        self.nonce = nonce;

        // Encrypt the data with our shared secret
        let encrypted_data: Vec<u8> = self.encrypt(data)
            .expect("Error encrypting data");

        println!("{}", data);

        let mut stream: &TcpStream = self.get_stream();

        /*let data: &[u8] = &vec![42; 11000000000];

        stream.write_all(data)?;
        stream.write_all(data)?;*/

        let data: &[u8] = &data;
        
        //     Req Type (1 byte) + Keep_alive (1 byte) + Nonce length (12 bytes)
        //     All data (Unknown) + SHA3-256 (32 bytes)
        let size: u64 = (1 + 1 + 12 + data.len() + 32) as u64;
        
        let hash: &[u8] = &sha3_256(data.to_vec());

        let packet: packets::FileStream = packets::FileStream {
            length: &size.to_be_bytes(),
            req_type: 1,
            keep_alive: true,
            filename: file,
            nonce: nonce,
            data: data,
            hash: hash,
        };

        stream.write_all(bincode::serialize(&packet))?;

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



pub struct Server
{
    host: String,
    port: u16,
    stream: Option<net::TcpStream>,
    kem_alg: oqs::kem::Kem,
    ciphertext: oqs::kem::Ciphertext,
    cipher: Aes256Gcm,
    nonce: GenericArray<u8, U12>
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
    }
}