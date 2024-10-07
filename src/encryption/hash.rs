use sha3::{Digest, Sha3_256};
use std::fs::File;
use std::io::{BufReader, Read};

pub fn sha3_256(buf: &[u8]) -> Vec<u8>
{
    let mut hasher = Sha3_256::new();

    hasher.update(buf);

    let bufhash: Vec<u8> = hasher.finalize().to_vec();

    bufhash
}

pub fn sha3_256_file(filepath: &str) -> Vec<u8>
{

    let file = File::open(filepath)
        .expect("Couldn't open file to read");

    let mut reader: BufReader<File> = BufReader::new(file);
    

    let mut hasher = Sha3_256::new();
    

    let mut buffer: [u8; 4096] = [0u8; 4096];

    loop
    {
        let bytes_read = reader.read(&mut buffer)
            .expect("Error reading bytes");

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }
    
    let result = hasher.finalize();

    result.to_vec()
}