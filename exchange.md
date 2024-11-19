# OQS AES256 + Kyber1024 + Dilithium5 Hybrid Key Exchange

1. Start a TCP Socket.

2. Both Client and Server initialize:
    - Signature algorithm: `let sigalg = sig::Sig::new(sig::Algorithm::Dilithium5)?;`
    - KEM algorithm: `let kemalg = kem::Kem::new(kem::Algorithm::Kyber1024)?;`

### Phase 1: Public Signature Key Exchange

3. Server generates Dilithium5 signature keys:
    `let (b_sig_pk, b_sig_sk) = sigalg.keypair()?;`

4. Server sends its signature public key (`b_sig_pk`) -> Client.

5. Client receives and **verifies** `b_sig_pk` to ensure it's valid and not malicious.

6. Client generates its Dilithium5 signature keys:
    `let (a_sig_pk, a_sig_sk) = sigalg.keypair()?;`

7. Client sends its signature public key (`a_sig_pk`) -> Server.

8. Server receives and **verifies** `a_sig_pk`.

### Phase 2: KEM Public Key Exchange with Signatures

9. Client generates Kyber1024 KEM keypair:
    `let (kem_pk, kem_sk) = kemalg.keypair()?;`

10. Client signs the KEM public key (`kem_pk`) with its signature secret key:
    `let kem_signature = sigalg.sign(kem_pk.as_ref(), &a_sig_sk)?;`

11. Client sends `(kem_pk, kem_signature)` -> Server.

12. Server verifies the signature on `kem_pk`:
    `sigalg.verify(kem_pk.as_ref(), &kem_signature, &a_sig_pk)?;`

13. Server encapsulates the shared secret (`ss`) using `kem_pk`:
    `let (kem_ct, b_kem_ss) = kemalg.encapsulate(&kem_pk)?;`

14. Server signs the ciphertext (`kem_ct`) with its signature secret key:
    `let ct_signature = sigalg.sign(kem_ct.as_ref(), &b_sig_sk)?;`

15. Server sends `(kem_ct, ct_signature)` -> Client.

16. Client verifies the signature on `kem_ct`:
    `sigalg.verify(kem_ct.as_ref(), &ct_signature, &b_sig_pk)?;`

17. Client decapsulates the shared secret (`ss`) using its KEM private key:
    `let a_kem_ss = kemalg.decapsulate(&kem_sk, &kem_ct)?;`

### Phase 3: Communication Using Shared Secret

18. Both parties now have the same shared secret (`ss`) and can use it as the key for symmetric encryption (e.g., AES256).

    - To encrypt: Use AES256 in GCM/CTR mode for secure communication.
    - To ensure correctness: Optionally, verify `a_kem_ss == b_kem_ss`.

### Additional Notes:
1. Validate all received public keys and signatures immediately to prevent malicious actors from tampering with the protocol.
2. Use secure randomness for key generation to prevent predictable keys.
3. Use authenticated encryption (e.g., AES-GCM) for post-exchange communication to ensure integrity and confidentiality.

