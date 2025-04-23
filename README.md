# STAR
STAR is a Post-Quantum Encryption Protocol written in Rust, which enables two peers to communicate in a socket using a high-level approach, this ensures a reliable, secure and easy to use way of communication.

To ensure a secure communcation, the protocol should use hybrid encryption, using the official  [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), of which these are used:
* [Crystals-Kyber 1024](https://pq-crystals.org/kyber/): For asymmetric key exchange
* [Crystals-Dilithium 5](https://pq-crystals.org/dilithium/): For signing messages in the key exchange

As well, a older standard is used in the protocol:
*  [NIST AES-256](https://www.nist.gov/publications/advanced-encryption-standard-aes): as the symmetric key algorithm.

> This repository contains the exchange.md which determinate how the exchange should be done to ensure a secure communication by the two parties as well as a simple implementation of the protocol written in Rust.

## Implementation
For the implementation of the STAR protocol it was preferred to use a memory safe language, one such as Rust, as well as the [OQS library](https://openquantumsafe.org/liboqs/)  for interacting with the PQ-Encryption standards.

> As of right now there is no working implementation of STAR, the one provided is a testing version which still does not work as stated in exchange.md.

## IMPORTANT
The protocol STAR is not field-tested, it is not prepared to be used in real world scenarios, and it is only a educational project, please do not use the protocol listed here nor the Rust implementation without proper knowledge about the risks involved in it.

