use sha3::{Digest, Sha3_256};

pub fn sha3_256(data: Vec<u8>) -> Vec<u8>
{
    let mut hasher = Sha3_256::new();

    hasher.update(data);

    let result: Vec<u8> = hasher.finalize().to_vec();
    
    result
}