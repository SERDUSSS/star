use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Request
{
    pub length: u16,           // Length of the full packet (All data included)
    pub req_type: u8,          // How to parse this packet
    pub keep_alive: bool,      // Close connection after this packet?
    pub packet_id: u64,        // Identifies the bulk of packets
    pub packet_number: u16,    // Number of this packet in this ID
    pub out_of: u16,           // Number of packets sent in this ID
    pub data: Vec<u8>,         // Encrypted data
    pub hash: [u8; 32],        // SHA3 32 bytes
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response
{
    pub length: u16,           // Length of the full packet (All data included)
    pub req_type: u8,          // How to parse this packet
    pub keep_alive: bool,      // Close connection after this packet?
    pub packet_id: u64,        // Identifies the bulk of packets
    pub packet_number: u16,    // Number of this packet in this ID
    pub out_of: u16,           // Number of packets sent in this ID
    pub data: Vec<u8>,         // Encrypted data
    pub hash: [u8; 32],        // SHA3 32 bytes
}