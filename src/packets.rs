
/*
    Request types:
        1 -> Stream (Data)
        2 -> FileStream (Files)    
 */

pub struct Stream
{
    pub length: u64,           // Length of the full packet (All data included)
    pub req_type: u8,          // How to parse this packet
    pub hash: [u8; 32],        // SHA3 32 bytes
    pub nonce: [u8; 12],       // Nonce (12 bytes)
    pub data: Vec<u8>,         // Encrypted data
}


pub struct FileStream
{
    pub length: u64,           // Length of the full packet (All data included)
    pub req_type: u8,          // How to parse this packet
    pub filename: [u8; 256],   // Filename of the file sent
    pub hash: [u8; 32],        // SHA3 32 bytes
    pub nonce: [u8; 12],       // Nonce (12 bytes)
    pub data: Vec<u8>,         // Encrypted data
}