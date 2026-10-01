# CryptoProvider

English | [Русский](../ru/CRYPTO.md)

Status: both suites are implemented and pass providertest. c25519 is the default, so results are
comparable with international work. GOST is the second suite and is compared with it on cost. The suite is chosen with -suite on the node, the client and the testbed; a
node publishes its suite next to its key, and a client on another suite refuses to start.

## Operations

| Operation | GOST (crypto/gost) | Default suite (crypto/c25519) |
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
- DeriveKey accepts any size from 1 to KeySize: wire takes 16 bytes for the control cell replay
  tag.
- An AEAD is safe for concurrent use: a node peels and wraps layers under one key from different
  goroutines. gogost's MGM keeps per-call state, so the GOST suite serialises calls with a lock.
  providertest checks this with concurrent Seal and Open.
- Nonces are assigned by wire: the provider neither stores nor counts them. The cell format rules
  out a nonce repeating under one key.
  In a 16-byte nonce the top bit is always zero, as MGM requires: the counter with the direction
  comes first and the random circuit id last.
- GenerateSigning issues the long-term pair for node authentication, separate from the ephemeral
  one.
- crypto/rand is the only standard-library crypto package used outside crypto/: randomness for
  identifiers, serial numbers and padding. It is not counted as a primitive.

## Signatures

The pki package takes signatures and hashes only through the CryptoProvider (Sign, Verify, Hash)
and has no primitives of its own.

| Key | What it signs | Domain string |
|---|---|---|
| CA key | node certificate | `jimichi/cert/v1\x00` |
| node signing key | certificate request | `jimichi/csr/v1\x00` |
| node signing key | node descriptor | `jimichi/descriptor/v1\x00` |

- The domain string precedes the body in the signed message only. A signature over one kind of
  object never verifies as a signature over another, even if the bodies coincide byte for byte.
- ca_id (the first 8 bytes) and cert_hash (32 bytes) come from the suite's Hash: SHA-256 or
  Streebog-256.
- Verify rejects a public key of small order before it looks at the signature: under such a key a
  signature for any message can be made without the private key. crypto/ed25519 verifies without
  the cofactor and accepts such keys (under the neutral point R = [S]B passes), so c25519 first
  decodes the key, requires its canonical encoding and rejects a point that the cofactor 8 takes
  to the neutral point. GOST rejects points off the curve and points of order 2 and 4; the neutral
  point has no affine encoding. providertest checks small-order keys for both suites.
- A rule for callers: in GOST the signing key comes from the same generator on the same curve as
  the ephemeral pair, so a signing key must never be used for key agreement, nor an agreement key
  for signing. The interface does not check this.
- The CA key and the node signing key are held in secmem buffers, and pki hands out only the
  public keys. The copies libraries make during generation and signing are listed under
  "Known gaps".

## Node keys

| Key | What it does | Lives |
|---|---|---|
| Node signing key | signs the certificate request and the descriptors | until the process ends |
| Link key | mixed into the handshake by whoever opens a link to the node, which authenticates the node on that link | until the process ends |
| Onion key | the client agrees the layer secret of a circuit setup with it | with -onion-rotate one period as the published key and the grace period after it; without rotation the link key serves in this role until the process ends |
| Hop keys of a circuit | open and seal the cells of one circuit at one node | until the circuit is torn down |
| Frame keys of a link | seal the frames of one link; derived from two ephemeral keys | until the link closes |

- The signing, link and onion keys are generated through the CryptoProvider straight into secmem
  buffers. An onion key is released, its buffer zeroed, at the end of its grace period
  (ARCHITECTURE, onion key epochs) and when the process ends.
- A setup costs the node one agreement per onion key it holds: one outside the grace period, two
  within it, which is two VKO on the GOST suite.
- Releasing an onion key wipes its secmem buffer only. The copies of the scalar that the
  libraries made during agreements stay on the heap until that memory is reused ("Known gaps").

## Memory (crypto/secmem)

- A buffer comes from mmap on pages of its own outside the Go heap, then mlock and
  madvise(MADV_DONTDUMP).
- Release: zeroing, munlock, munmap. A second Release does not panic.
- Process: prctl(PR_SET_DUMPABLE, 0), RLIMIT_CORE=0. This closes ptrace and /proc/pid/mem for the
  same uid and does nothing against root.
- In a container mlock is bounded by RLIMIT_MEMLOCK. A node checks the budget at start and refuses
  to run below 64 KiB, or when locking was asked for and failed. A rotating node holds one locked
  page per onion key, two at most, and does not take a new onion key whose page is not locked.
- Every measure is switched by configuration, so its contribution can be measured:

| Flag | What it turns on |
|---|---|
| -keymem all | every measure, the default |
| -keymem none | baseline build: keys on the Go heap, no locking, no dump exclusion, no zeroing |
| -keymem offheap,lock,dontdump | everything but zeroing: zeroing's effect on a process dump shows only with keys on the heap (none against zero), since off-heap pages are gone from the process after munmap |
| -keymem offheap,lock,dontdump,zero | any subset; lock and dontdump need offheap |
| -harden | prctl(PR_SET_DUMPABLE, 0) and RLIMIT_CORE=0 for the process |

## Libraries

- GOST: gogost 5.14.1 by Sergey Matveev (GPLv3), module github.com/pedroalbanese/gogost. The
  author's domain go.cypherpunks.su did not answer and the Go proxy has no copy, so a mirror with
  the same code is used, pinned in go.sum. The mirror was checked: no network or file I/O, and
  unsafe only in the fast XOR, as in the original. Known-answer tests in crypto/gost check the
  standards: VKO against RFC 7836, the KDF against R 50.1.113-2016, Kuznyechik-MGM against
  RFC 9058, Streebog-256 against RFC 6986.
- The peer's point is checked before VKO: coordinates below p, the point on the curve and not in
  the subgroup of order 2 or 4. The library does not do this itself, and an off-curve point would
  let a peer draw the node's link or onion key out piece by piece. For mixed points the cofactor
  of 4 is cleared inside VKO.
- A UKM longer than 8 bytes (the public key in the link handshake) is first hashed down to 8 bytes
  with Streebog: RFC 7836 defines a 64-bit factor. The full value still seeds the KDF.
- Signing feeds the Streebog digest in gogost's byte order. Only this system verifies the
  signatures, so interoperability with other implementations is not claimed.
- c25519: golang.org/x/crypto (curve25519, chacha20poly1305, hkdf). Ed25519 signing follows
  RFC 8032 on filippo.io/edwards25519, directly over the secmem buffer. Since Go 1.25 crypto/ed25519
  caches the expanded key under a weak pointer to the key: on mmap memory the runtime aborts, and on
  the heap the expanded key lives until garbage collection.
- GenerateSigning in c25519 reads the seed from crypto/rand straight into the secmem buffer and
  derives the public key from it by RFC 8032 (section 5.1.5) on filippo.io/edwards25519, wiping
  its own scalars and digests. crypto/ed25519.GenerateKey would leave the seed and the expanded key
  on the heap, while the node signing key lives as long as the process. The copies inside SHA-512
  and edwards25519 remain and are listed under "Known gaps". A test checks the public key and the
  signatures against ed25519.NewKeyFromSeed.

## Known gaps

secmem protects only the buffers the code manages itself. Libraries make their own copies, and
some of them live long:

| Where | What | How long |
|---|---|---|
| x/crypto chacha20poly1305 | the AEAD working key, copied into the cipher struct | the whole life of the circuit or link, never wiped |
| crypto/ecdh | the X25519 scalar, the node's link and onion keys included, and the shared secret | until the freed heap memory is reused, which can be after the onion key itself was released |
| x/crypto hkdf, crypto/hmac | the PRK, the HMAC pads (key XOR a constant), the last derived block | until the heap memory is reused |
| Ed25519 generation and signing | the SHA-512 state with the seed or the nonce prefix, a copy of the scalar in edwards25519 | until the heap memory is reused; generation and signing always wipe their own scalars and digests, -keymem none included |
| gogost, Kuznyechik | the round keys in the cipher struct, the first two being the key itself | the whole life of the circuit or link; Destroy wipes them, except under -keymem none |
| gogost, KDF | the HMAC-Streebog pads holding the VKO secret and the circuit secret | until the heap memory is reused |
| gogost, GOST R 34.10 and VKO | the scalar as math/big and intermediate points, the node's link and onion keys included | until the heap memory is reused, which can be after the onion key itself was released; the provider wipes the number, not the copies made inside the computation |
| gogost, GOST R 34.10 signing | the CA or node signing scalar and the one-time number k as math/big, intermediate points; k and the signature give back the key | until the heap memory is reused; the copies reappear at every signature: the request, the certificate, every descriptor refresh |

gogost arithmetic on math/big is not constant time. The node's link and onion keys could leak
through VKO timing to an adversary who times the node's responses; side-channel attacks are
outside the threat model.

The Go heap does not move objects, but freed memory is not wiped, and goroutine stacks are copied
when they grow. Locking and dump exclusion do not reach these copies. Measuring how many copies
remain and how long they live is part of block 4 of the research programme.
