# CryptoProvider

English | [Русский](../ru/CRYPTO.md)

Status: both suites are implemented and pass providertest. c25519 is the default, so results are
comparable with international work. GOST is the second suite and is compared with it on cost. The
suite is chosen with -suite on the node, the client and the testbed; a node publishes its suite
next to its key, and a client on another suite refuses to start.

## Operations

| Operation | GOST (crypto/gost) | Default suite (crypto/c25519) |
|---|---|---|
| Ephemeral pair | GOST R 34.10-2012, 256 bit, paramSetA (TC26) | X25519 |
| Key agreement | VKO_GOSTR3410_2012_256 (R 50.1.113-2016; RFC 7836, 4.3.1), UKM from the transcript hash, then the KDF | X25519, then HKDF-SHA-256 with the transcript hash |
| KDF | KDF_GOSTR3411_2012_256 (R 50.1.113-2016; RFC 7836, 4.5) | HKDF-SHA-256 (RFC 5869) |
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
	Agree(priv *secmem.Buffer, peerPub []byte, ctx Context) (*secmem.Buffer, error)
	MixKey(chain, secret *secmem.Buffer, ctx Context) (*secmem.Buffer, error)
	DeriveKey(secret *secmem.Buffer, purpose string, ctx Context, size int) (*secmem.Buffer, error)
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

const ContextSize = 32

type Context struct{ /* the suite and the transcript hash */ }

func NewContext(p CryptoProvider, exchange string, parts ...[]byte) (Context, error)
func (c Context) Sum() []byte
func (c Context) Suite() Suite
func (c Context) Valid() bool

func TranscriptBytes(s Suite, exchange string, parts ...[]byte) ([]byte, error)
func Label(s Suite, purpose string) ([]byte, error)
func DeriveLabel(s Suite, purpose string) ([]byte, error)
```

Decisions taken:
- Secrets cross the interface only as *secmem.Buffer. Public keys and signatures are []byte: they
  are not secret, and a type per suite would complicate wire.
- Agree, MixKey and DeriveKey take a Context: the hash of the exchange transcript, 32 bytes. It
  binds every secret and every key to the public keys of both sides, the parameters of the
  exchange, the suite and the scheme version. The provider refuses the zero Context and a context
  of another suite, so no key can be derived without a transcript. The layout and the formulas
  are under "Key derivation".
- The provider builds the KDF label from the scheme version, the suite and the purpose. A caller
  passes the purpose only and cannot supply a label string of its own.
- MixKey chains a second agreement onto the first: the result depends on both secrets and stays
  KeySize long.
- KeySize reports the AEAD key length so that wire never hardcodes 32 bytes.
- DeriveKey in both suites takes a secret of exactly KeySize bytes and a size from 1 to KeySize;
  a key shorter than KeySize is the prefix of the full one. wire takes 16 bytes for the control
  cell replay tag and 8 bytes for each counter offset.
- An AEAD is safe for concurrent use: a node peels and wraps layers under one key from different
  goroutines. gogost's MGM keeps per-call state, so the GOST suite serialises calls with a lock.
  providertest checks this with concurrent Seal and Open.
- Nonces are assigned by the caller: the provider neither stores nor counts them. link numbers the
  frames of one direction of a link from zero and puts the number in the last 8 bytes of the
  nonce, the rest zero. wire builds the nonce of a cell layer from the direction, the circuit id
  and the counter. The cell format rules out a nonce repeating under one key. In a 16-byte nonce
  the top bit is always zero, as MGM requires: wire puts the counter with the direction first and
  the random circuit id last, and link leaves the leading bytes zero.
- GenerateSigning issues the long-term pair for node authentication, separate from the ephemeral
  one.
- crypto/rand is the only standard-library crypto package used outside crypto/: randomness for
  identifiers, serial numbers and padding. It is not counted as a primitive.

## Key derivation

Every secret and every key depends on the transcript of its exchange, on the suite and on the
scheme version. A substituted public key, mode, suite or version on either side gives different
keys, and the first AEAD check fails.

### Label

`label = ASCII("jimichi/v1/" || suite || "/" || purpose)`, the suite being `c25519` or `gost`.
A label holds no 0x00 byte and is at most 50 bytes long.

| purpose | Label length, c25519 / GOST | Derived by | Key size |
|---|---|---|---|
| `agree` | 23 / 21 | the provider, inside Agree | 32 |
| `mix` | 21 / 19 | the provider, inside MixKey | 32 |
| `setup` | 23 / 21 | wire, the setup layer key | 32 |
| `cell` | 22 / 20 | wire, the hop key | 32 |
| `setup/replay` | 30 / 28 | wire, the control cell replay tag | 16 |
| `counter/fwd`, `counter/bwd` | 29 / 27 | wire, the counter offsets | 8 |
| `link/i2r`, `link/r2i` | 26 / 24 | link, the frame keys | 32 |

- A purpose and an exchange name: `[a-z0-9]+(/[a-z0-9]+)*`, 1 to 32 bytes.
- `agree`, `mix` and anything that starts with `transcript/` are reserved to the provider:
  DeriveKey with such a purpose returns an error, so a caller cannot reproduce the output of
  Agree or MixKey.
- The signature domain strings (section "Signatures") are versioned on their own and are not
  part of this scheme.

### Transcript

```
T  = ASCII("jimichi/v1/" || suite || "/transcript/" || exchange) || 0x00 || u8(n)
     || n times: u16be(part length) || part
th = Hash(T)        SHA-256 or Streebog-256, 32 bytes
```

- 1 to 255 parts, each 1 to 65535 bytes.
- The layout is unambiguous: the string holds no 0x00, and after it come a separator, the number
  of parts and the length of every part. The same bytes cut at other places give another hash.
- NewContext takes the hash and the suite name from the provider it is given, so a context is as
  trustworthy as that provider: the type guarantees that a context is present, not that it is the
  suite hash of a transcript. wire, link and relay pass the provider of the suite itself.
- NewContext copies the parts into T and hashes it at once: a slice of a cell body cannot change
  between two derivations.
- The transcript consists of public data and is not signed with the node signing key. Sum
  returns a copy of the hash.

Circuit setup, exchange `setup`, one context per hop:

| No. | Part | Bytes | Client | Node |
|---|---|---|---|---|
| 1 | version | 1 | the cell format version | the cell format version |
| 2 | hop index | 1 | the number of the hop in the chain | the counter field of the control cell |
| 3 | link id | 8, big endian | chosen for the hop | from the cell header |
| 4 | onion key | public key | from the verified descriptor | the public half of the onion key being tried |
| 5 | client ephemeral key | public key | generated | the bytes at the start of the layer |

T is 120 bytes long on c25519 and 182 on GOST.

Link, exchange `link`:

| No. | Part | Bytes |
|---|---|---|
| 1 | version | 1 |
| 2 | mode | 1: 0x00 anonymous, 0x01 authenticated |
| 3 | initiator ephemeral key | as in the hello after the mode byte |
| 4 | responder ephemeral key | as sent |
| 5 | responder link key, in mode 0x01 only | the initiator takes it from the descriptor, the responder uses its published one |

T in modes 0x00 and 0x01: 109 and 143 bytes on c25519, 171 and 237 on GOST.

### Formulas

c25519: HKDF-SHA-256 (RFC 5869: Extract in section 2.2, Expand in section 2.3, one output
block), `info(p) = label(p) || 0x00 || th`.

| Operation | Computation |
|---|---|
| Agree | `Z = X25519(priv, pub)`; `PRK = HMAC(key = th, Z)`; `HMAC(PRK, info(agree) \|\| 0x01)` |
| MixKey | `PRK = HMAC(key = chain, secret)`; `HMAC(PRK, info(mix) \|\| 0x01)` |
| DeriveKey | `HMAC(secret, info(purpose) \|\| 0x01)[0:size]` |

GOST: VKO_GOSTR3410_2012_256 and KDF_GOSTR3411_2012_256 (RFC 7836, sections 4.3.1 and 4.5),
`KDF(K, label, seed) = HMAC_Streebog256(K, 0x01 || label || 0x00 || seed || 0x01 || 0x00)`.

| Operation | Computation |
|---|---|
| Agree | `UKM = th[0:8]` as a little-endian number, zero replaced by one; `KEK = VKO(priv, pub, UKM)` after the point checks; `KDF(KEK, label(agree), th)` |
| MixKey | `KDF(chain, label(mix), th \|\| secret)` |
| DeriveKey | `KDF(secret, label(purpose), th)[0:size]` |

The GOST profile:
- K_in is always 256 bits: the KEK, the output of Agree or the output of MixKey.
- label is a constant of the scheme without 0x00, seed is always 32 bytes, 64 in MixKey. RFC 7836
  (4.5) requires the protocol to assign label and seed and recommends fixing their lengths.
- The output is one block, at most 32 bytes.
- A 64-bit UKM is taken from the start of the transcript hash, and the whole hash goes into the
  seed. RFC 7836 (4.3.1) allows a UKM of up to half the public key size and recommends 64 bits or
  more when at least one side uses a static key. A wider factor would lengthen the second scalar
  multiplication.
- In MixKey the second secret takes the seed position. The function is the same, but the seed is
  not a public value here: this departs from the usual use of KDF_GOSTR3411_2012_256. The
  reasoning: HMAC is treated as a pseudorandom function in the key chain and as an extractor in
  the message, which holds secret, so the output is unknown as long as at least one of the two
  secrets is unknown. This work gives no formal proof for the composition.

### Who calls what

Setup: the client and the node build the same `ctx = NewContext(p, "setup", ...)`,
`secret = Agree(.., ctx)`, then DeriveKey under the same ctx for `setup`, `cell`, `counter/fwd`,
`counter/bwd`. The node also derives `setup/replay`; the client does not derive the replay tag.
A node holding two onion keys builds a context for each of them: a
layer built for the key of one epoch does not open under the key of another.

Link, both agreements under one context:

| Mode | Agreements | The key the frame keys are derived from |
|---|---|---|
| 0x00 | ephemeral with ephemeral (ee) | `ee` |
| 0x01 | the initiator's ephemeral key with the responder's link key (es), then ee | `MixKey(chain = es, secret = ee, ctx)` |

The frame keys: DeriveKey with `link/i2r` and `link/r2i`. The responder's first frame confirms
the whole transcript: if a single byte of it differs between the sides, the frame does not open.

The key pair check at node start, exchange `relay/keycheck`: the node generates a one-time pair
and, under a context made of its published link key and the one-time public key, agrees a secret
from both sides. The two secrets must be equal; no key is derived from them and both are released
at once. A node whose published key does not agree with its private key (the public key of
another pair, or one the agreement refuses) does not start:
it would otherwise confirm no authenticated link and, without -onion-rotate, where the link key
also serves as the onion key, open no setup. The pairs of the onion key ring are not checked this
way.

### Rules for changes

- The scheme version `v1` changes with any change to the transcript layout, to the formulas, or
  to the name or size of an existing purpose. Versions are not compatible with each other, and
  there is no version negotiation.
- A new purpose does not change the version: it adds a row to the label table and a golden
  vector in crypto/providertest.
- The golden vectors pin the composition: the hashes of three transcripts, every derived key,
  MixKey and Agree on fixed keys, for both suites. The comment next to them says how to recompute
  the values without this code. The VKO examples of RFC 7836 (appendix B, examples 7 and 8) are on
  the 512-bit paramSetA, so the GOST primitives are checked against the examples of the standards
  in the tests of crypto/gost, and the composition on the 256-bit paramSetA is pinned by the
  vectors of the scheme with the intermediate values (the transcript hash, the UKM, the KEK)
  written down in crypto/providertest. They were computed by an independent implementation that
  is not part of the repository; everything but the KEK is a hash or an HMAC and can be
  recomputed with any Streebog implementation.

The provider checks are the same in both suites and run in this order: sizes of the secrets, the
context, the label, the public key.

| Argument | Rule | Error |
|---|---|---|
| priv | the private key length of the suite | ErrBadKeySize |
| secret, chain | exactly KeySize | ErrBadKeySize |
| size | 1 to KeySize | ErrBadKeySize |
| ctx | made by NewContext with a provider of the same suite | ErrBadContext |
| purpose, exchange | the name format; in DeriveKey not one reserved to the provider | ErrBadLabel |
| transcript parts | 1 to 255, each 1 to 65535 bytes | ErrBadContext |
| peerPub | the length; a point of small order (on c25519 X25519 itself refuses it); in GOST also a point off the curve or with a coordinate not below p | ErrBadPublicKey |

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
| Frame keys of a link | seal the frames of one link; derived from the agreement of the two ephemeral keys and, in the authenticated mode, also from the agreement with the responder's link key (section "Key derivation") | until the link closes |

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
- Off-heap pages, locking, dump exclusion and process hardening work in the Linux build only. On
  other systems a buffer is a slice on the Go heap that reports itself as not locked, and release
  does nothing but zero it, and that only with zeroing on. Process hardening returns an error
  there: with the default flags a node, a client and jimichi enroll refuse to start and run only
  with -harden=false and a -keymem without lock.
- In a container mlock is bounded by RLIMIT_MEMLOCK. A node checks the budget at start and refuses
  to run below 64 KiB, or when locking was asked for and failed. A rotating node holds one locked
  page per onion key, two at most, and one more that it gives back right before it makes the
  next key. It does not take a new onion key whose page is not locked.
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
  the same version number in its code is used, pinned in go.mod and go.sum (pseudo-version of
  commit 44a1f1ec2524). Whether its code equals the author's release has not been checked against
  an independent source, the check is planned
  ([#50](https://github.com/jimichi-org/jimichi/issues/50)). The library packages of the mirror
  were checked: no network or file I/O, and unsafe only in the fast XOR. Known-answer tests in
  crypto/gost check the standards: VKO against RFC 7836, the KDF against R 50.1.113-2016,
  Kuznyechik-MGM against RFC 9058, Streebog-256 against RFC 6986.
- The peer's point is checked before VKO: coordinates below p, the point on the curve and not in
  the subgroup of order 2 or 4. The library does not do this itself, and an off-curve point would
  let a peer draw the node's link or onion key out piece by piece. For mixed points the cofactor
  of 4 is cleared inside VKO.
- The UKM for VKO is the first 8 bytes of the transcript hash as a little-endian number, zero
  replaced by one; the whole hash seeds the KDF. The technique follows KEG (RFC 9189, section
  8.3.1), where the UKM is the first 16 bytes of a hash and zero is replaced by one in the same
  way. The provider takes no other UKM length.
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
| x/crypto chacha20poly1305 | the AEAD working key, copied into the cipher struct | the whole life of the circuit or link, never wiped; building the AEAD state per call from the secmem key is planned ([#39](https://github.com/jimichi-org/jimichi/issues/39)) |
| crypto/ecdh | the X25519 scalar, the node's link and onion keys included, and the shared secret | until the freed heap memory is reused, which can be after the onion key itself was released |
| x/crypto hkdf, crypto/hmac | the HMAC pads (key XOR a constant) holding the PRK, the circuit secret, the link secret (ee or the MixKey output) and the MixKey chain key; the SHA-256 state holding the X25519 shared secret and the second secret of MixKey; the last derived block | until the heap memory is reused; the provider zeroes its own copy of the PRK |
| Ed25519 generation and signing | the SHA-512 state with the seed or the nonce prefix, a copy of the scalar in edwards25519 | until the heap memory is reused; generation and signing always wipe their own scalars and digests, -keymem none included |
| gogost, Kuznyechik | the round keys in the cipher struct, the first two being the key itself | the whole life of the circuit or link; Destroy wipes them unless zeroing is off (-keymem none or a list without zero) |
| gogost, KDF | the HMAC-Streebog pads holding the VKO secret, the circuit secret, the link secret (ee or the MixKey output) and the MixKey chain key; the Streebog message buffer holding the second secret of MixKey | until the heap memory is reused; the provider assembles the MixKey seed in a secmem buffer |
| gogost, GOST R 34.10 and VKO | the scalar as math/big and intermediate points, the node's link and onion keys included | until the heap memory is reused, which can be after the onion key itself was released; the provider wipes the number unless zeroing is off (-keymem none or a list without zero), never the copies made inside the computation |
| gogost, GOST R 34.10 signing | the CA or node signing scalar and the one-time number k as math/big, intermediate points; k and the signature give back the key | until the heap memory is reused; the copies reappear at every signature: the request, the certificate, every descriptor refresh |

gogost arithmetic on math/big is not constant time. The node's link and onion keys could leak
through VKO timing to an adversary who times the node's responses; side-channel attacks are
outside the threat model.

The Go heap does not move objects, but freed memory is not wiped, and goroutine stacks are copied
when they grow. Locking and MADV_DONTDUMP do not reach these copies: only secmem pages are locked,
so key copies on the heap and on stacks can be written to swap, and with -harden=false they can
end up in a core dump. Locking all process memory is planned
([#36](https://github.com/jimichi-org/jimichi/issues/36)). Measuring how many copies remain and
how long they live is planned as block 4 of the research programme
([#24](https://github.com/jimichi-org/jimichi/issues/24)) and has not been done yet.
