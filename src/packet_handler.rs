use crate::packets::*;
use crate::encryption::hash;
use rand::Rng;
use bincode;

const MAX_PACKET_SIZE: usize = 1073740800; // 1GB - 1024 Bytes

fn generate_random_id() -> u64
{
    let mut rng = rand::thread_rng();

    let random_u64: u64 = rng.gen();

    random_u64
}

pub fn split_data(data: &[u8]) -> Vec<normal::Request> {
    let total_packets: usize = (data.len() + MAX_PACKET_SIZE - 1) / MAX_PACKET_SIZE;
    let mut packets: Vec<normal::Request> = Vec::with_capacity(total_packets);
    let mut offset: usize = 0;
    
    let pack_id: u64 = generate_random_id();

    for i in 0..total_packets {
        let end: usize = std::cmp::min(offset + MAX_PACKET_SIZE - 32, data.len()); // Adjust for header size
        let packet_data: Vec<u8> = data[offset..end].to_vec();
        let length: usize = packet_data.len() + 16; // Adjust length to include header
        
        let packet: normal::Request = normal::Request {
            length: length as u16,
            req_type: 4,
            keep_alive: true,
            packet_id: pack_id,
            packet_number: i as u16,
            out_of: total_packets as u16,
            data: packet_data,
            hash: [0u8;32], // Set appropriate value
        };

        // Serialize the packet
        let serialized_packet: Vec<u8> = bincode::serialize(&packet).expect("Failed to serialize packet");

        // Generate the hash
        let hash = hash::sha3_256(serialized_packet);

        // Convert the hash to [u8; 32]
        let hash_array: [u8; 32] = hash.try_into().expect("Hash length mismatch");
        
        let packet_with_hash = normal::Request {
            hash: hash_array,
            ..packet // Copy all other fields from the original packet
        };

        packets.push(packet_with_hash);
        offset = end;
    }
    
    packets
}