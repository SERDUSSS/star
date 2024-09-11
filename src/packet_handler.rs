use crate::{encryption::hash, packets::Stream};
use rand::Rng;
use bincode;

const MAX_PACKET_SIZE: usize = 1073740800; // 1GB - 1024 Bytes
const CHUNK_SIZE: usize = 1 * 1024 * 1024 * 1024; // 1 GB

fn generate_random_id() -> u64
{
    let mut rng = rand::thread_rng();

    let random_u64: u64 = rng.gen();

    random_u64
}