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
	// Destroy drops the cipher; whether its key copy is wiped depends on the library.
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

- A buffer comes from mmap on pages of its own outside the Go heap, then mlock and
  madvise(MADV_DONTDUMP).
- Release: zeroing, munlock, munmap. A second Release does not panic.
- Process: prctl(PR_SET_DUMPABLE, 0), RLIMIT_CORE=0. This closes ptrace and /proc/pid/mem for the
  same uid and does nothing against root.
- In a container mlock is bounded by RLIMIT_MEMLOCK. A node checks the budget at start and refuses
  to run below 64 KiB, or when locking was asked for and failed.
- Every measure is switched by configuration, so its contribution can be measured:

| Flag | What it turns on |
|---|---|
| -keymem all | every measure, the default |
| -keymem none | baseline build: keys on the Go heap, no locking, no dump exclusion, no zeroing |
| -keymem offheap,lock,dontdump,zero | any subset; lock and dontdump need offheap |
| -harden | prctl(PR_SET_DUMPABLE, 0) and RLIMIT_CORE=0 for the process |

## Library candidates

- GOST: go.cypherpunks.su/gogost (GPLv3; the module path and the presence of the KDF and MGM are
  to be verified).
- c25519: golang.org/x/crypto (curve25519, chacha20poly1305, hkdf). Ed25519 signing follows
  RFC 8032 on filippo.io/edwards25519, directly over the secmem buffer. Since Go 1.25 crypto/ed25519
  caches the expanded key under a weak pointer to the key: on mmap memory the runtime aborts, and on
  the heap the expanded key lives until garbage collection.

## Known gaps

secmem protects only the buffers the code manages itself. Libraries make their own copies, and
some of them live long:

| Where | What | How long |
|---|---|---|
| x/crypto chacha20poly1305 | the AEAD working key, copied into the cipher struct | the whole life of the circuit or link, never wiped |
| crypto/ecdh | the X25519 scalar, the node's long-term key included, and the shared secret | until the freed heap memory is reused |
| x/crypto hkdf, crypto/hmac | the PRK, the HMAC pads (key XOR a constant), the last derived block | until the heap memory is reused |
| Ed25519 signing | the SHA-512 state with the nonce prefix, a copy of the scalar in edwards25519 | until the heap memory is reused; signing always wipes its own scalars and digests, -keymem none included |

The Go heap does not move objects, but freed memory is not wiped, and goroutine stacks are copied
when they grow. Locking and dump exclusion do not reach these copies. Measuring how many copies
remain and how long they live is part of block 4 of the research programme.
