# Architecture

English | [Русский](../ru/ARCHITECTURE.md)

## What the system is

Messages travel through a chain of three relay nodes under nested encryption. No node knows both
the sender and the recipient, key material exists only in the node's memory, and every cell is
the same size.

## Components

| Component | Purpose |
|---|---|
| client | builds the circuit, encrypts the layers, sends payload and cover cells, receives replies |
| relay | strips its own layer and forwards; writes nothing to disk |
| crypto | CryptoProvider: two primitive suites behind one interface |
| crypto/secmem | key buffers outside the Go heap: mlock, no dumps, zeroed on release |
| wire | cell format and nested route encryption |
| vault | client container with two independent volumes: a decoy password and the real one |
| lab | experiment runs, the observer, metrics and reports in artifacts/ |
| web | testbed dashboard: network graph, what each node learns, live attack result |

## Message flow

```
client-a -> relay-1 -> relay-2 -> relay-3 -> client-b
```

1. The client picks three nodes from a directory of addresses and long-term keys.
2. It agrees an ephemeral session key with each node separately. A node's keys are meant to be
   vouched for by a node bundle signed along the chain from the CA. The pki package implements the
   bundle check (section "Node authentication"); the client does not run it yet.
3. The client wraps the message in three layers: the outer one for relay-1, the inner one for
   relay-3.
4. Each node strips exactly its own layer and learns only the next hop.
5. Session keys live until the circuit is torn down, and their buffers are then zeroed. Copies the
   libraries keep are described in CRYPTO.

## Cell format

Every cell is 512 bytes, payload and cover cells alike.

| Field | Size | Purpose |
|---|---|---|
| version | 1 | format version |
| kind | 1 | data, control, link padding |
| circuit | 8 | circuit identifier, different on every link |
| counter | 8 | cell number, the source of the nonce and of replay protection |
| body | 494 | layers: three 16-byte tags, the length prefix and the payload |

- The nonce never travels: it is derived from the direction, the circuit identifier and the
  counter. A key belongs to one hop of one circuit, so the pair never repeats under it.
- Every layer is an AEAD over the next layer. The associated data covers the version, the kind,
  the counter and the hop index, so a cell cannot be moved to another position in the chain.
- The circuit identifier is not authenticated: every link rewrites it.
- The layer of hop i occupies the first 494 - 16 * i bytes of the body. After stripping its layer
  a node refills the body with random bytes, so every link carries the same size and the position
  in the chain is invisible on the wire.
- Payload and cover cells share one outer kind, "data". The cover flag sits inside the innermost
  layer, in the top bit of the length field, where only the exit sees it. Nodes on the way,
  including the entry that knows the client, cannot tell a cover cell from a payload cell.
- Inside the innermost layer: two bytes of length, the data, random padding. Three hops leave 444
  bytes for a message, in both suites.
- The setup cell holds four hops on c25519 and three on GOST: a GOST public key is 64 bytes
  against 32, and every setup layer grows by the difference.
- A node keeps a window of accepted counters and drops a replay: forwarding one would hand an
  active observer a free timing mark.

## Link encryption

A cell never crosses a link in the clear: it travels inside an encrypted frame. Without this layer
the cell header is visible on the wire, and its counter is the same on every link of the chain: an
observer at the entry and at the exit would link a flow by matching numbers, with no statistics.

- Handshake: the initiator sends an ephemeral public key, the responder answers with its own. The
  secret of the two ephemeral keys gives the link forward secrecy.
- The client knows the long-term key of the entry node and mixes it into the secret, so the first
  link is authenticated. Links between nodes are anonymous: they hide headers from a passive
  observer, while the onion layers bind the content to the nodes the client chose.
- Two keys are derived from the secret, one per direction. The nonce is the frame number in that
  direction.
- A frame is the 512-byte cell plus a 16-byte tag, 528 bytes. After the handshake the wire carries
  only frames of one size: no identifiers, no counters.
- The link layer takes its primitives from the same CryptoProvider, so it works on the GOST suite
  as well.
- A link padding cell lives on one link only: the sender of the frame makes it and the receiving
  end of the link drops it before it reaches a circuit. From the outside it looks like any other
  frame.

## Sending modes

| Mode | How cells leave | What an observer sees |
|---|---|---|
| Immediate | a cell leaves as soon as there is something to send, cover is added on top | the send pattern follows the conversation |
| Constant rate | cells leave on a schedule and a payload takes a cover slot | the pattern on the link does not depend on the conversation |

The second mode is the countermeasure against flow linking. Its price is queueing: a message waits
for its slot, so latency grows at a low schedule rate and shrinks at a high one.

A constant rate at the client is not enough: a node that forwards a cell at once carries the phase
of the client's schedule onto the next link, and it reaches the exit. So a node can send on its own
clock.

- Node parameter: the send period. Zero means forwarding at once, as without the measure.
- Each circuit and each direction gets its own queue and timer on the node. Every tick sends one
  cell from the queue, or a link padding cell when the queue is empty.
- The first tick falls at a random moment within the period. Otherwise the timer would start with
  the circuit setup, which crosses the chain almost at once, and the client's phase would match
  the node's again.
- The queue is bounded, so neither the node's memory nor the latency grows without limit when a
  client sends faster than the node's period. A cell that arrives at a full queue is dropped and
  counted as dropped. The loss is not visible on the wire: frames leave on every tick either way.
- There is no shuffling across circuits: every circuit runs over its own TCP connections, so
  there is nothing to mix on a link.

Entry and middle send on their own clock in both directions, the exit only backwards: it has
nothing to send forwards. The price: at each such step a cell waits half a period on average, about
two and a half periods per round trip, and the links between nodes and from the entry to the
client carry a constant stream per circuit even while the client is silent.

The measure hides timing from an observer on a link. A neighbouring node removes the link
encryption and tells padding from a real cell by its kind, so it does not help against a node.

## Return path

A reply travels the same chain in reverse: the exit applies its layer, every relay towards the
client adds its own, and only the client strips them all. The direction enters the nonce, so a
forward and a backward cell never share one under the same key. The backward counter is separate,
and each relay keeps its own replay window per direction.

The exit answers every data cell with exactly one backward cell: a message with its reply, a cover
cell with a cover reply. Replies to messages only would show every node on the way back, by their
number and timing, which cells were real. The count is the same in every mode; the timing matches
only when the delivery at the exit takes constant time or the nodes send on their own clocks.

## Circuit setup

Setup takes one control cell of the same 512 bytes, with no extra round trips.

- The client knows the addresses of the nodes and their long-term public keys.
- For each node it generates an ephemeral pair and agrees a shared secret with that node's
  long-term key, bound to the identifier of the link into that node.
- Two keys are derived from the secret, one for the control cell and one for data cells, and a
  replay tag.
- The control cell is nested like a data cell: the layer of each node holds its ephemeral public
  key, the address of the next node, the identifier of the next link and the layer for the next
  node.
- The hop index travels in the counter field: a node must know its position before it can tell how
  much of the body belongs to its layer.
- After stripping its layer a node refills the cell to 512 bytes and forwards it.
- A node remembers a tag of every control cell it opened for as long as its key lives, and drops a
  copy, including after the original circuit has closed. Otherwise the copy would create the hop
  key again and the counters would restart from zero under the same key. The tag is derived from
  the shared secret under a KDF label of its own rather than read off the wire: keys that differ
  by a point of small order (8 points on X25519, 4 on GOST) and an X25519 encoding with the top
  bit set give one secret.
- The number of tags is bounded (-setup-cache); a full node refuses new circuits rather than
  forget tags. A control cell on a link that already carries a circuit is dropped before the key
  agreement and takes no tag.
- The cache protects only while the layer agreement key dies with the process: a restart clears
  the tags. The agreement key therefore lives only in process memory and never reaches a disk; a
  long-term node key, where there is one, only signs it and takes no part in the layer agreement
  itself.

An empty next address marks the exit node.

Circuit teardown:

- A circuit is bound to the link its control cell arrived on. A cell with the same identifier on
  another link is dropped, and so is a second control cell with an identifier already in use.
- Closing a link anywhere closes the neighbouring links of the circuit in both directions, so the
  break reaches the client and the exit node.
- Circuit keys are released once every goroutine using them has stopped.
- The client sees the break as its reply channel closing and exits. The orchestrator restarts it
  on a new circuit.

## Node authentication

The pki package implements the chain of trust from the CA key to the node keys that go into
circuit setup, together with certificate issuance and verification. The CA key only signs
certificates and takes no part in the layer agreement: compromising it lets an attacker certify a
node of their own, but it does not open past sessions.

### Chain of trust

| Link | What it binds | Signed by |
|---|---|---|
| Trust anchor | the CA public key as the string `<suite>:<base64>`; ca_id is the first 8 bytes of Hash(key) | nothing, it reaches the client as configuration |
| Node certificate | suite, serial number, ca_id, validity, name, address, node signing key | the CA key |
| Node descriptor | certificate hash, link key, onion key, epoch, validity | the node signing key |
| Certificate request | a nonce chosen by the CA, name, address, node signing key | the node signing key |

- The address in the certificate is exactly the host:port the client dials or writes as the next
  node's address.
- The onion key is meant for circuit setup, the link key for the link to the entry node. The
  descriptor carries both fields so the onion key can change independently of the link key.
- The request is used only for issuance and is never shown to clients. It proves possession of the
  signing key, and the nonce chosen by the CA proves freshness. Request.Check accepts a request
  only if the nonce matches and the name and address match the operator roster.
- Identity.Install installs a certificate only if the signing key, suite, name, address and
  validity all match. The node does not check the CA signature: it has no anchor. Whoever issues
  the certificate must therefore verify the node's bundle against the anchor after the install,
  as a client does.
- The CA key and the node signing key are generated through the CryptoProvider straight into
  secmem buffers. Close releases them; callers defer it.

### Formats

The formats are binary: big-endian integers, variable-length fields with a one-byte length prefix
and a hard maximum, times in unix seconds (int64). The signature is the last field. What is signed
is the domain string followed by the body without the signature; the domain string itself is not
transmitted.

| Object | Body | Domain string |
|---|---|---|
| Certificate v1 | version 1, suite, serial 16, ca_id 8, not_before, not_after, name, address, signing key | `jimichi/cert/v1\x00` |
| Descriptor v1 | version 1, suite, epoch u32, published, expires, cert_hash 32, link key, onion key | `jimichi/descriptor/v1\x00` |
| Request v1 | version 1, suite, nonce 16, name, address, signing key | `jimichi/csr/v1\x00` |

- Name: 1 to 32 characters from `a-z`, `0-9` and `-`.
- Address: 1 to 64 bytes (the size of the address field in a control cell), printable ASCII
  0x21..0x7e only, parsed as host:port with a non-empty host; the port is decimal, with no sign or
  leading zero, from 1 to 65535. wire drops trailing NULs from an address, so an address with a
  NUL, a space or a byte outside ASCII could name one node and lead to another. The port has one
  spelling because the client compares addresses byte for byte.
- Keys and signatures are at most 128 bytes. cert_hash is the Hash of the whole certificate,
  signature included.
- Parsing rejects an unknown version (ErrVersion), an unknown suite (ErrSuite), a field over its
  maximum, trailing bytes and any input that does not re-encode to itself (ErrFormat). Every object
  has one canonical encoding. A suite other than the provider's is rejected right after parsing
  (ErrSuite).
- The node bundle for clients: JSON
  `{"v":1,"suite":"c25519","cert":"<base64>","descriptor":"<base64>"}`. Parsing accepts only the
  spelling Bundle.Marshal writes: lower-case keys in this order, no spaces, repeats, omissions or
  trailing data, base64 in its canonical form. The suite and the descriptor are not empty.
- The unsigned bundle (pki.Unsigned) serves the measurement without authentication: an empty
  certificate, a zero cert_hash, an empty signature. An empty certificate is allowed only there,
  and Verify rejects such a bundle (ErrFormat).

Validity:

- The clock skew allowance Skew = 2 min applies to lower bounds only (not_before, published), so no
  window is ever extended past its end.
- A certificate whose not_after is not after its not_before is rejected (ErrCertTime), as it is at
  issuance.
- A descriptor expires no later than its certificate (expires <= not_after) and lives at most 24 h.
- Identity.Refresh signs a new descriptor with expires = min(now + ttl, not_after). Without a
  certificate it returns ErrNoCert, and after not_after it withdraws the bundle.

### Verification order

pki.Verify checks a node bundle against the anchor, the address being dialled and the current time.
The first failure stops the check; every check after parsing has its own error:

1. the anchor suite, bundle parsing, its version and suite (ErrFormat, ErrVersion, ErrSuite): the
   suite is settled before any key is parsed as a curve point;
2. certificate parsing (ErrFormat, ErrVersion, ErrSuite);
3. ca_id (ErrUnknownCA) and the CA signature (ErrCertSignature);
4. certificate validity (ErrCertTime);
5. the certificate address equals the dialled address byte for byte (ErrWrongAddr);
6. descriptor parsing and cert_hash (ErrFormat, ErrVersion, ErrSuite, ErrCertMismatch);
7. the node signing key's signature (ErrDescSignature);
8. descriptor validity, expires <= not_after, lifetime at most 24 h (ErrDescTime);
9. the link and onion keys have the length of the suite's agreement key (ErrKeySize).

- pki.VerifyChain runs this check for every node of the chain and requires addresses, signing keys
  and onion keys to be pairwise distinct (ErrDuplicate).
- pki.Unverified reads the same bundles checking only format, suite, key length and repeats, with
  no signatures, validity or addresses. It is the baseline for measuring what authentication is
  worth. It also rejects repeated addresses and onion keys (ErrDuplicate), so when several nodes
  are substituted, both the unauthenticated measurement and the testbed must give every
  substituted node a key of its own.
- Request.Check at issuance checks the suite (ErrSuite), the nonce (ErrNonce), the name and
  address against the roster (ErrRoster) and the request signature (ErrRequestSignature).

## What is recorded during measurements

| Source | Data |
|---|---|
| client | send and receive timestamps per cell, losses, flow identifier |
| relay | aggregated counters on stdout once a minute and on loopback on request: accepted, forwarded, delivered, dropped, padding. No flow identifiers. The counters are not published on the network: polled often, they would show which ticks carried a real cell |
| network | traffic captures at the entry and the exit for the correlation attack |
| memory | dumps of the relay process in the key extraction scenario |

Everything lands in artifacts/ together with the run configuration and the generator seed.

## Client container

Nodes store nothing, the client stores the message history. The container holds two independent
volumes: one opens with a decoy password, the other with the real one. The volume key comes from
the password through Argon2id, the file carries no header revealing how many volumes exist, and
unused space is filled with random data.

The property is measured, not declared: entropy and the NIST STS battery show that the file is
indistinguishable from random data. Its limits (traces at the filesystem and drive level, an
adversary with several snapshots) are stated in LIMITATIONS.

## Package layout

| Package | Purpose | Depends on |
|---|---|---|
| crypto | CryptoProvider interface | crypto/secmem |
| crypto/gost, crypto/c25519 | primitive suites | crypto, secmem, external libraries |
| crypto/suite | picks a suite by name for entry points and the testbed | crypto/gost, crypto/c25519 |
| crypto/secmem | key memory | x/sys/unix |
| crypto/providertest | contract conformance tests | crypto |
| wire | cell format, layers, replay window | crypto, crypto/secmem |
| link | link encryption between neighbours, frames of one size | crypto, crypto/secmem, wire |
| pki | certificate, descriptor and request of a node, issuing and checking | crypto, crypto/secmem, wire |
| relay | relay node, sending on its own clock | crypto, crypto/secmem, link, wire |
| client | send, receive, cover traffic | crypto, crypto/secmem, link, wire |
| vault | container with two volumes | crypto, crypto/secmem |
| lab/* | scenarios, observer, metrics, reports | client, relay, link, crypto/suite |
| web | testbed dashboard | lab |
| cmd/relay, cmd/client, cmd/lab | entry points and configuration | the packages above |

Rule: relay, client and wire know nothing about lab. The experiment harness depends on the system,
not the other way round.

## Deployment

- deploy/compose: docker-compose with three relays and two clients, the development mode.
- deploy/kind and deploy/base: the same set in a Kubernetes cluster, for the defence demo.
  The manifests hold no Secret with keys, volumes are tmpfs in RAM, the root filesystem is
  read-only.
