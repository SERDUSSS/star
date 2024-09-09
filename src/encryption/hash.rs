use sha3::{Digest, Sha3_256};

pub fn sha3_256(data: Vec<u8>) -> [u8; 32]
{
    let mut hasher = Sha3_256::new();

    hasher.update(data);

    let result: Vec<u8> = hasher.finalize().to_vec();
    
    let fixed_array: [u8; 32] = result
        .try_into()
        .expect("Vec<u8> should have exactly 32 elements");

    fixed_array
}