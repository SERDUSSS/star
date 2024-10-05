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
pub enum SendPKError {
    #[error("Error sending Public Key to peer")]
    SendPKError,
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