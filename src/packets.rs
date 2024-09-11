use serde::{Serialize, Deserialize, Debug};

/*
    Request types:
        1 -> Stream (Data)
        2 -> FileStream (Files)    
 */

#[derive(Serialize, Deserialize, Debug)]
pub struct Stream
{
    pub length: u64,           // Length of the full packet (All data included)
    pub req_type: u8,          // How to parse this packet
    pub keep_alive: bool,      // Close connection after this packet?
    pub nonce: [u8; 12],
    pub data: Vec<u8>,         // Encrypted data
    pub hash: [u8; 32],        // SHA3 32 bytes
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileStream
{
    pub length: u64,           // Length of the full packet (All data included)
    pub req_type: u8,          // How to parse this packet
    pub keep_alive: bool,      // Close connection after this packet?
    pub filename: [u8; 256],
    pub nonce: [u8; 12],
    pub data: Vec<u8>,         // Encrypted data
    pub hash: [u8; 32],        // SHA3 32 bytes
}