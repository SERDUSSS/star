use thiserror::Error;

#[derive(Error, Debug)]
pub enum ErrorGeneratingSecureKeys {
    #[error("Error generating keys for communication")]
    ErrorSendingData,
}

#[derive(Error, Debug)]
pub enum ErrorGeneratingKeyPair {
    #[error("Error generating keys for communication")]
    ErrorSendingData,
}

#[derive(Error, Debug)]
pub enum WritePKError {
    #[error("Error writing Public Key to peer")]
    WritePKError,
}

#[derive(Error, Debug)]
pub enum ReadPKError {
    #[error("Error reading Public Key to peer")]
    ReadPKError,
}

#[derive(Error, Debug)]
pub enum OQSEncryptError {
    #[error("Error encrypting data with OQS, probably Shared Secret")]
    OQSEncryptError,
}

#[derive(Error, Debug)]
pub enum OQSDecryptError {
    #[error("Error decrypting data with OQS, probably Shared Secret")]
    OQSDecryptError,
}

#[derive(Error, Debug)]
pub enum HandShakeError {
    #[error("Error stablishing connection to peer")]
    HandShakeError,
}

#[derive(Error, Debug)]
pub enum ErrorSendingData {
    #[error("Error sending data to peer")]
    ErrorSendingData,
}

#[derive(Error, Debug)]
pub enum ErrorReceivingData {
    #[error("Error receiving data from peer")]
    ErrorReceivingData,
}

#[derive(Error, Debug)]
pub enum EncryptError {
    #[error("Error while trying to encrypt data")]
    EncryptionError,
}

#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("Error while trying to decrypt data")]
    DecryptionError,
}
