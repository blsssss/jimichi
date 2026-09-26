# CryptoProvider

English | [Русский](../ru/CRYPTO.md)

Status: the contract is fixed, the c25519 suite is implemented and passes providertest. The GOST
suite is in progress.

## Operations

| Operation | GOST (crypto/gost) | Comparison suite (crypto/c25519) |
|---|---|---|
| Ephemeral pair | GOST R 34.10-2012, 256 bit, paramSetA (TC26) | X25519 |
| Key agreement | VKO GOST R 34.10-2012 (R 50.1.113-2016), with UKM | X25519 |
| KDF | KDF_GOSTR3411_2012_256 (R 50.1.113-2016) | HKDF-SHA-256 |
| AEAD | Kuznyechik-MGM (R 1323565.1.026-2019), 16-byte nonce, 16-byte tag | XChaCha20-Poly1305, 24-byte nonce, 16-byte tag |
| Signature | GOST R 34.10-2012, 256 bit | Ed25519 |
| Hash | Streebog-256 | SHA-256 |

Different nonce sizes and overheads are visible through the interface: wire hardcodes no sizes.

## Interface

```go
type Suite uint8

type CryptoProvider interface {
	Suite() Suite

	GenerateEphemeral() (priv *secmem.Buffer, pub []byte, err error)
	Agree(priv *secmem.Buffer, peerPub, ukm []byte) (*secmem.Buffer, error)
	DeriveKey(secret *secmem.Buffer, label []byte, size int) (*secmem.Buffer, error)
	KeySize() int

	NewAEAD(key *secmem.Buffer) (AEAD, error)

	GenerateSigning() (priv *secmem.Buffer, pub []byte, err error)
	Sign(priv *secmem.Buffer, msg []byte) ([]byte, error)
	Verify(pub, msg, sig []byte) bool

	Hash(data ...[]byte) []byte
}

type AEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, ad []byte) []byte
	Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
	Destroy()
}
```

Decisions taken:
- Secrets cross the interface only as *secmem.Buffer. Public keys and signatures are []byte: they
  are not secret, and a type per suite would complicate wire.
- ukm is mandatory in both suites: it binds the shared secret to one session. In GOST it is the
  standard VKO parameter, in c25519 it goes in as the HKDF salt.
- KeySize reports the AEAD key length so that wire never hardcodes 32 bytes.
- Nonces are assigned by wire: the provider neither stores nor counts them. The cell format rules
  out a nonce repeating under one key.
  In a 16-byte nonce the top bit is always zero, as MGM requires: the counter with the direction
  comes first and the random circuit id last.
- GenerateSigning issues the long-term pair for node authentication, separate from the ephemeral
  one.

## Memory (crypto/secmem)

- A buffer comes from mmap outside the Go heap, then mlock and madvise(MADV_DONTDUMP).
- Release: zeroing, munlock, munmap. A second Release does not panic.
- Process: prctl(PR_SET_DUMPABLE, 0), RLIMIT_CORE=0.
- In a container mlock is bounded by RLIMIT_MEMLOCK. The buffer budget is checked, and a node that
  does not fit refuses to start.
- PR_SET_DUMPABLE=0 also closes ptrace and /proc/pid/mem for the same uid. It is a switch, so a
  baseline run can measure what the measure is worth.

## Library candidates

- GOST: go.cypherpunks.su/gogost (GPLv3; the module path and the presence of the KDF and MGM are
  to be verified).
- c25519: golang.org/x/crypto (curve25519, chacha20poly1305, hkdf). Ed25519 signing follows
  RFC 8032 on filippo.io/edwards25519, directly over the secmem buffer. Since Go 1.25 crypto/ed25519
  caches the expanded key under a weak pointer to the key: on mmap memory the runtime aborts, and on
  the heap the expanded key lives until garbage collection.

## Known gaps

- Ciphers expand the key into a round key schedule on the Go heap (Kuznyechik, the ChaCha state).
  Wiping it depends on the library and the garbage collector may copy it. Recorded in
  LIMITATIONS.md.
- X25519 through crypto/ecdh copies the scalar to the heap for the duration of the call, and that
  copy cannot be wiped. The SHA-512 state during signing is on the heap as well and holds the nonce
  prefix, which is as sensitive as the key, for the duration of the call. The internal copy of the
  scalar in edwards25519 is not wiped.
