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

1. The client obtains the signed bundles of the three chain nodes from its entry node, the only
   node it connects to. A bundle is the node's certificate from the CA and a descriptor with the
   node keys, signed by the node signing key.
2. Before the circuit setup the client checks every bundle against the trust anchor (section
   "Node authentication"). If any node fails the check, the client refuses to build the circuit.
   It then agrees an ephemeral session key with each node separately.
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
| counter | 8 | cell number on the link, the source of the nonce and of replay protection; a value of its own on every link |
| body | 494 | layers: three 16-byte tags, the length prefix and the payload |

- The nonce never travels: it is derived from the direction, the circuit identifier and the
  counter. A key belongs to one hop of one circuit, so the pair never repeats under it.
- The counter takes a value of its own on every link of the circuit. At setup each node derives
  two offsets from the secret it shares with the client, one per direction, and adds its offset
  modulo 2^62 to the counter of every cell it passes on. The client knows the offsets of all nodes and seals the
  layer of each node with the value that arrives on the link into that node. The setup cell does
  not grow for it.
- The cell number stays below 2^60 in each direction, so the values of one link never repeat
  while the circuit lives.
- Every layer is an AEAD over the next layer. The associated data covers the version, the kind,
  the counter on the link into the node and the hop index, so a cell cannot be moved to another
  position in the chain and a node cannot shift the counter without breaking the layer.
- The circuit identifier is rewritten on every link and is not part of the associated data: the
  layer is bound to it through the nonce.
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
- Counters on every link follow strictly one after another: a node accepts a cell only if its
  counter is one above the last one accepted, modulo 2^62. Every node except the exit takes the
  first value in each direction as it comes, since it depends on the offsets of the other nodes.
  The exit expects a fixed first forward value, and the client checks the number of every reply
  (section "Return path"). A copy, a gap, a step back
  or a jump closes the circuit and the cell goes no further: forwarding a replay would hand an
  active observer a free timing mark, and a gap or a reorder would carry on to every later link.
- The exit knows the counter the first forward cell arrives with: the client puts that value in
  the exit's setup layer. Cells lost at the start of a circuit at any node reach the exit as a
  break in the order, and the exit closes the circuit.
- A node opens a forward cell first and checks its counter after. A cell that does not open is
  dropped and does not affect the order.
- The client assigns the counter when it writes the cell to the link, after the random delay, so
  cells leave in counter order.

## Link encryption

A cell never crosses a link in the clear: it travels inside an encrypted frame. Without this layer
the cell header is visible on the wire: an observer on a link would see the kind, the circuit
identifier and the counter of every cell.

- Handshake: the initiator sends a mode byte and an ephemeral public key. The responder answers
  with its own ephemeral public key and one frame: a link padding cell sealed as frame 0 of its
  direction. The secret of the two ephemeral keys gives the link forward secrecy.
- That frame confirms the keys before any cell is sent. The initiator finishes the handshake only
  once the frame has opened under the keys it derived and holds a padding cell, within the
  deadline of whoever dials. Otherwise the handshake fails, and the initiator has sent nothing but
  its hello. The responder sends the frame in both modes, and the frames of its direction go on
  from number 1. The responder's part of the handshake is its key and that one frame: 32 + 528
  bytes on c25519, 64 + 528 on GOST.
- The initiator mixes the responder's link key, taken from a verified descriptor, into the
  secret: the client does it for the entry node, a node for the next node of the circuit. Every
  link of a circuit is therefore authenticated to the node it leads to: only the holder of that
  link key derives the frame keys, so a responder without it cannot produce the confirmation and
  is sent no cell. The responder does not authenticate the initiator.
- A node extends a circuit only to a node of its roster whose verified descriptor it holds
  (section "Node authentication"). A setup that names any other address is refused without a
  connection and counted (refused_extend). A next node that does not finish the handshake is
  sent no setup cell, and the failure is counted (failed_extend). In both cases the setup cell
  is counted with the dropped ones, like that of any setup that fails.
- Without node authentication (-auth=false) a node holds no verified link keys: it extends to
  any address, and its link to the next node is anonymous. An anonymous link hides headers from
  a passive observer only. This is the measurement baseline.
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
  client sends faster than the node's period. A cell that arrives at a full queue closes the
  circuit: a node never loses a cell of a circuit, since a loss would break the counter order on
  the later links. Such a close is counted with the closed circuits.
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
and each relay checks the counter order in each direction separately. Like the forward one, it
takes a value of its own on every link: the exit and every relay on the way back add their backward
offset.

A relay cannot check a backward cell: its inner layers do not open for it. It therefore passes back
only cells of kind "data" with the next counter in turn, and any other cell closes the circuit. The
exit numbers its replies from zero. The client knows the offsets of all nodes, recovers the number
of every reply and accepts only the next one: a reply out of turn, or one that does not open,
closes the circuit on the client's side as well. The client counts the cells it has written to the
link and closes the circuit on a reply numbered at or past that count: the exit answers every cell
once.

A reply too long for a cell is replaced by a cover reply under the same number. The length is
checked before anything is sealed, so no nonce is used twice. Any other failure to seal a reply
closes the circuit.

The exit answers every data cell with exactly one backward cell: a message with its reply, a cover
cell with a cover reply. Replies to messages only would show every node on the way back, by their
number and timing, which cells were real. The count is the same in every mode; the timing matches
only when the delivery at the exit takes constant time or the nodes send on their own clocks.

## Circuit setup

Setup takes one control cell of the same 512 bytes, with no extra round trips.

- The client knows the addresses of the nodes and their onion keys from verified descriptors.
- For each node it generates an ephemeral pair and agrees a shared secret with that node's onion
  key, bound to the identifier of the link into that node.
- Two keys are derived from the secret, one for the control cell and one for data cells, two
  counter offsets and a replay tag.
- The control cell is nested like a data cell: the layer of each node holds its ephemeral public
  key, the address of the next node, the identifier of the next link and the layer for the next
  node.
- The hop index travels in the counter field: a node must know its position before it can tell how
  much of the body belongs to its layer.
- After stripping its layer a node refills the cell to 512 bytes and forwards it.
- A node with a roster forwards the control cell only to a roster node, over a link authenticated
  with that node's link key (section "Link encryption"). A setup that names another address, or
  whose next node fails the link handshake, ends at this node, and the link it arrived on closes.
- A node remembers a tag of every control cell it opened for as long as it holds the onion key
  that opened it, and drops a copy, including after the original circuit has closed. Otherwise
  the copy would create the hop key again and the counters would restart from zero under the same
  key. The tag is derived from the shared secret under a KDF label of its own rather than read
  off the wire: keys that differ by a point of small order (8 points on X25519, 4 on GOST) and an
  X25519 encoding with the top bit set give one secret.
- Every onion key has a tag cache of its own, bounded by -setup-cache. A full cache refuses new
  setups under its key rather than forget tags, and under that key only: the refusal ends when
  the node publishes its next onion key. A control cell on a link that already carries a circuit
  is dropped before the key agreement and takes no tag.
- The cache protects only because the tags and the onion key go together: a released key takes
  its tags with it, and a restart clears both. The onion key therefore lives only in process
  memory and never reaches a disk; the node signing key only signs the descriptor that carries it
  and takes no part in the layer agreement itself.

An empty next address marks the exit node. The exit has no next link, so the field for its
identifier in the exit's layer carries the counter of the first forward cell, and the setup cell
does not grow.

Onion key epochs:

- With -onion-rotate (1 h by default and on the testbed) a node opens setup layers with an onion
  key of its own, separate from the link key, and replaces it every period: it generates a new
  pair in a secmem buffer, raises the epoch by one and signs a descriptor with the new key at
  once, without waiting for the signing timer. The link key stays the same for the life of the
  process.
- The replaced key is held for a grace period after the rotation: the descriptor lifetime plus
  the clock allowance (-descriptor-ttl + Skew, 22 min on the testbed). By then every descriptor
  that names it has expired, also for a verifier whose clock is behind by the allowance and in
  the mirror of a node that could not fetch again. The key is then released, its buffer is zeroed
  and its tags are forgotten: a setup cell recorded for it no longer opens with anything the node
  holds.
- A node holds at most two onion keys, and a rotation waits until the replaced key is released.
  The time between rotations is therefore -onion-rotate, or the grace period when that is
  longer: 1 h on the testbed, 1 h 2 min with the default descriptor lifetime of 1 h.
  -onion-rotate must not be shorter than -descriptor-ttl.
- While two keys are held the node tries both on every setup, in one order and to the end: two
  agreements and two attempts to open the layer whichever key the client used, so the time a
  setup takes does not show the epoch. At most one key opens the layer, and the tag goes into the
  cache of that key.
- No key is released while a setup is being opened: the release waits for it.
- The node reads its clocks once a second and takes the moment of a rotation and of a release
  twice: by the wall clock and by the running time of the host (the monotonic clock). It acts as
  soon as either says the moment has come. The running time stands still while the host sleeps,
  so after a sleep the first reading releases a key whose grace has ended by the wall clock and
  then rotates once. A wall clock set back postpones neither moment: the running time still
  brings it. A wall clock set forwards brings both early, which costs clients a refused setup and
  no secrecy. A descriptor is always signed for the key that is current at that moment.
- A rotation that fails, because there is no memory for the new key or its page cannot be
  locked, leaves the published key in place. The node tries again every second and counts the
  attempts (onion_rotate_failed). Between rotations it holds one key page and gives it back right
  before the next key is made, so that the key finds room when locked memory is used up.
- A circuit that is already built does not notice a rotation: its cell keys come from its setup
  and live until the circuit is torn down.
- -onion-rotate 0 is the measurement baseline: the link key opens the setup layers as well, for
  the life of the process, under epoch 0, and the node prints one WARNING line at start. The lab
  harness runs its nodes this way.
- Without node authentication a descriptor carries no lifetime. After a rotation the node serves
  an unsigned bundle with the new key and epoch, the other nodes fetch it again within a minute,
  and the replaced key is held for the same grace period.

Circuit teardown:

- A circuit is bound to the link its control cell arrived on. A cell with the same identifier on
  another link is dropped, and so is a second control cell with an identifier already in use.
- Closing a link anywhere closes the neighbouring links of the circuit in both directions, so the
  break reaches the client and the exit node.
- A node closes a circuit itself when a cell arrives out of turn, a cell of another kind or one
  it cannot wrap comes back, a cell finds no room in its queue, a cell cannot be written to either
  neighbour, or the exit cannot seal a reply. The close takes the same path as a closed link and
  is counted with the closed circuits.
- A link that has opened no circuit by the setup deadline after its handshake is closed.
- A frame that cannot be written within the write deadline is such a failed write: the peer has
  stopped reading, and a node sending on its own clock would otherwise wait for it. It is counted
  with the closed circuits and with the expired deadlines.
- A circuit that carries no cell in either direction for the idle timeout, or that reaches its
  lifetime, is torn down by closing its inbound link and counted with the expired circuits, not
  with the closed ones. Link padding does not count as traffic.
- Circuit keys are released once every goroutine using them has stopped.
- The client sees the break as its reply channel closing and exits. The orchestrator restarts it
  on a new circuit.

## Node limits

Every limit is a node parameter with a default. A negative value turns a limit off, so its cost
can be measured on its own, with two exceptions: a burst cannot be negative and is refused at start
(the rate is what turns that limit off), and the per-address handshake cap stays on, at 4, when the
shared cap is off, unless it is set to -1 itself.

| Limit | Default | Why |
|---|---|---|
| handshake deadline, -handshake-timeout | 2 s | an initiator sends its hello at once, so a silent peer holds a slot only briefly |
| dial and handshake towards the next hop | 5 s, fixed | a silent next hop holds neither the setup nor the node shutdown |
| setup deadline, -setup-timeout | 10 s | the client and the previous node send the control cell right after the handshake |
| write deadline, -write-timeout | 4 periods and at least 1 s; 5 s without own-clock sending | a peer that stops reading does not stall the sender |
| idle circuit, -idle-timeout | 5 min | an abandoned circuit stops sending padding; the testbed client sends every 200 ms |
| circuit lifetime, -circuit-lifetime | 24 h | bounds how long one set of circuit keys lives |
| concurrent handshakes, -max-handshakes | 32 | more would only queue for the CPU |
| concurrent handshakes from one address, -max-handshakes-per-source | an eighth of -max-handshakes and at least 1, so 4; also 4 when -max-handshakes is off | one address cannot hold every handshake slot |
| open inbound links, -max-links | 512 | the memory of their circuits stays inside a 128 MiB pod |
| links from one address, -max-links-per-source | 32 | one peer cannot take every slot; a client needs a handful of circuits |
| new links from one address, -source-link-rate, -source-link-burst | 10 per second, bursts of up to 50 | every link costs a key pair and an agreement |
| setups from one address, -source-setup-rate, -source-setup-burst | 0.2 per second, bursts of up to 10 | every setup costs an agreement with each onion key the node holds, a dial onwards and a tag kept as long as its key |

- A connection is admitted or refused when it is accepted, before any key agreement. A control
  cell is checked after the link handshake and before the agreement with the onion keys. A
  refused connection is closed without an answer.
- A full tag cache (-setup-cache) refuses setups only under the onion key it belongs to. With
  rotation the refusal ends when the next key is published, one period later at most; without
  rotation it ends at a restart.
- Every connection costs its address a token of the link rate, admitted or refused, and the limits
  of one address are checked before the shared ones: retrying against a full node spends the
  address's own allowance and leaves the shared slots to others.
- On the testbed the per-address limits are on at the entry relay-1 and off on relay-2 and
  relay-3, where every circuit arrives from the previous relay's one address (LIMITATIONS). A
  network policy (deploy/base/network.yaml) lets only client pods reach the cell port of relay-1
  and only the previous relay reach that of relay-2 and relay-3; the info port stays open to the
  namespace.
- One address is an IPv4 address or an IPv6 /64 prefix. The table of addresses lives only in
  memory, holds at most 16384 of them and forgets an address once it has no open links and its
  buckets have refilled. A new address past the bound is refused and counted with the per-address
  refusals, known addresses are still served.
- Every control cell spends a setup token before it is opened, so an address whose links have
  closed stays in the table until its setup bucket refills: up to 50 s at the default rate and
  burst.
- Refusals and expired deadlines are added to the aggregated counters, without addresses or
  identifiers.
- A temporary accept error, such as running out of file descriptors, is retried with a pause from
  5 ms doubling up to 1 s. If accepting stops for good, the node exits with an error and the
  orchestrator restarts it; the health check reports ready only while the node accepts.

## Node authentication

The client takes node keys only from a bundle verified against the trust anchor, and a node takes
the link key of the next node only from such a bundle. The pki package implements the chain of
trust from the CA key to the node keys, certificate issuance and verification; cmd/relay,
cmd/client and cmd/jimichi use it. The CA key only signs certificates and takes no part in the
layer agreement.

### Chain of trust

| Link | What it binds | Signed by |
|---|---|---|
| Trust anchor | the CA public key as the string `<suite>:<base64>`; ca_id is the first 8 bytes of Hash(key) | nothing, it reaches the client as configuration (ConfigMap jimichi-ca) |
| Node certificate | suite, serial number, ca_id, validity, name, address, node signing key | the CA key |
| Node descriptor | certificate hash, link key, onion key, epoch, validity | the node signing key |
| Certificate request | a nonce chosen by the CA, name, address, node signing key | the node signing key |

- The address in the certificate is exactly the host:port the client dials or writes as the next
  node's address.
- The onion key goes into circuit setup, the link key into the link that leads to the node: from
  the client to the entry, from a node to the next node. With -onion-rotate the onion key is a
  pair of its own that changes by epochs while the link key stays (section "Circuit setup",
  onion key epochs). With -onion-rotate 0 a node publishes one agreement key in both fields.
- The request is used only for issuance and is never shown to clients. It proves possession of the
  signing key, and the nonce chosen by the CA proves freshness. Request.Check accepts a request
  only if the nonce matches and the name and address match the operator roster.
- Identity.Install installs a certificate only if the signing key, suite, name, address and
  validity all match. The node does not check the CA signature: it has no anchor. Whoever issues
  the certificate must therefore verify the node's bundle against the anchor after the install,
  as pki.Verify does for a client; jimichi enroll does exactly that.
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
  NUL, a space or a byte outside ASCII could name one node and lead to another. Host and port
  have one spelling each (host names in lower case without a trailing dot, IP literals in
  canonical form) because Verify compares addresses byte for byte. A host is an IP literal or
  DNS labels of a-z, 0-9 and the hyphen joined by dots, no label empty or starting or ending
  with a hyphen: an address carries nothing a URL would read as a path, a query, user
  information or another port.
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
- The roster a node receives after its certificate: JSON
  `{"anchor":"<suite>:<base64>","nodes":[{"name":"<name>","addr":"<host:port>"},...]}`. Parsing
  accepts only the spelling Roster.Marshal writes, at most 4 KiB (pki.MaxRoster); names and
  addresses are well formed and pairwise distinct (ErrFormat, ErrDuplicate).
- The descriptor mirror: JSON `[{"addr":"<host:port>","bundle":{...}},...]`, sorted by address,
  every bundle in its own canonical spelling; parsing accepts only that. The mirror carries no
  signature of its own: each bundle in it is verified like any other.

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

### Client check

- Before any network request: with -auth (the default) an empty -ca is fatal, and the anchor
  suite must equal -suite.
- The client requests /descriptors from its entry, the first node of -nodes, and from no other
  node: a 5 s timeout per request and a 256 KiB limit, retrying up to 30 times 1 s apart only on
  a connection error or a 503 answer; decoding is strict. A chain node with no bundle in the
  answer stops the client with
  `refusing to build the circuit: node <address>: the entry holds no bundle for it`.
- pki.VerifyChain checks every node of the chain. On the first error the client exits with
  `refusing to build the circuit: node <address>: <reason>`, or, when a node repeats, with
  `refusing to build the circuit: nodes <address> and <address>: pki: node repeated in the chain`.
  There is no fallback to unverified keys and no partial chain. On success it logs one line per
  node: the signing key fingerprint and the certificate and descriptor validity.
- The onion key from the descriptor goes into circuit setup, the entry node's link key into
  link.Dial. client.Dial refuses a node with an empty key or a key of the wrong size: an empty
  link key would make the link to the entry anonymous.
- With -auth=false the client takes the bundles from its entry in the same way, reads them
  through pki.Unverified and logs one WARNING line. The unverified keys of every hop then come
  from the entry alone: whoever answers for the entry chooses them. A node run with -auth=false
  serves an unsigned bundle (pki.Unsigned). This is the baseline for measuring what
  authentication is worth.

### Certificate issuance

Certificates are issued by `jimichi enroll` (cmd/jimichi) outside the cluster: on the operator's
machine or the CI runner. scripts/enroll.sh runs it for every node of the testbed.

1. The operator passes a roster: for each node the name and address for its certificate, two
   local addresses that reach the node's admin port and descriptor port, and the hash of the
   node signing key. The node prints this hash once at start, before any port serves
   (identity_hash=). scripts/enroll.sh reads it from the log of the pod's current container
   through the kube API (kubectl logs) and requires exactly one such line. Names, addresses, local
   addresses and hashes must be well formed and pairwise distinct.
2. The process sets the secmem policy (-keymem, -harden). If memory locking was requested and
   does not work, issuance does not start.
3. Each node gets POST /csr with a fresh 16-byte nonce and answers with a request signed by its
   signing key. Request.Check matches the nonce, name and address against the roster, the key
   hash in the request must equal the hash from the log, and the signing keys of the nodes must
   be pairwise distinct. A node that has already taken a certificate, valid or expired, answers
   POST /csr with 409, and enroll prints the command that restarts it.
4. Only when every request has passed and the roster of the run fits the 4 KiB a node accepts
   (pki.MaxRoster) is the CA key created in a secmem buffer. The CA issues every certificate
   and its key is released at once (Close): it lives for the issuance only.
5. Each certificate goes to its node with PUT /cert. The node accepts a certificate only if it
   has taken none before, within 60 s of POST /csr (pki.InstallWindow), once per request and only
   with a not_before no earlier than the request time minus Skew; otherwise it answers 409 with
   the error class. It then installs the certificate, signs a descriptor and answers 204, or 400
   if the install is refused. Sending the installed certificate again while it is valid gets 204,
   so a retry after a lost answer goes through.
6. enroll reads /descriptor of every node and checks the whole chain with pki.VerifyChain against
   the new anchor, exactly as a client does.
7. enroll sends every node the roster with PUT /roster: the anchor and the name and address of
   every node of this run, the same bytes to each (section "Roster, peer descriptors and the
   mirror").
8. Only when every node has accepted the roster is the anchor printed on stdout. On any error
   stdout stays empty and the exit code is 1.

- A certificate is installed once per node process: an installed certificate is never replaced, not
  even an expired one, and re-enrollment needs a node restart, which brings a new identity. Install
  does not check the CA signature, so without this rule anyone who reaches the admin port could
  replace a working certificate with their own.
- Installation across the nodes is not atomic. If issuance fails after the first PUT /cert, the
  nodes that already took a certificate keep it under a discarded CA until they restart, and
  clients refuse them. enroll lists those nodes on stderr, together with the nodes whose answer
  was lost or a 5xx (may hold), and prints the `kubectl rollout restart` command for them;
  enroll.sh prints the same guidance. A roster that fails on some node is reported the same way:
  the nodes that hold or may hold a roster of the discarded CA are listed with their restart
  command. Issuance runs again after the restart.
- enroll's -timeout is at most 60 s, so the whole run fits the window in which a node waits for
  its certificate.
- The request, the certificate and the roster travel over `kubectl port-forward` to one specific
  pod, to the node's admin port 127.0.0.1:9101, the same one that serves the counters. The kube
  API lets the operator reach the pod and its log by kubeconfig and the pods/portforward and
  pods/log rights. A port-forward reaches whatever process listens on the pod's loopback, so the
  request is tied to the node by the key hash from the container log: a request under another
  key is refused and no certificate is issued. With -auth a node refuses to start unless the
  -stats address is a loopback IP. Request bodies on that port are capped at 4 KiB.
- The anchor goes into ConfigMap jimichi-ca (key anchor), from there into the JIMICHI_CA variable
  and the client's -ca flag. After a new issuance enroll.sh restarts the client.
- A Windows host has no mlock and no prctl: enroll.sh passes `-keymem zero -harden=false`, and
  enroll warns that the CA key stays in unlocked memory while it issues. The locked path runs in
  Linux: WSL2 and CI.
- `jimichi keygen-ca` prints the anchor of a key that is thrown away at once. e2e uses it to check
  that a client holding a foreign anchor refuses to build the circuit.

### Roster, peer descriptors and the mirror

- A node takes one roster per process: only after its certificate, within 60 s of installing it
  (pki.InstallWindow), and only on the admin port. A roster that does not list the node's own
  name and address is refused (400), and so is a roster under whose anchor the node's own served
  bundle does not verify (pki.Verify at its own address): the roster names the anchor of the CA
  that certified the node. Its node list is not authenticated; it only narrows the set of nodes
  that CA certified, since a peer counts only with a descriptor verified under that anchor. A
  roster before the certificate, after the window, after another roster or while the node
  serves no valid descriptor gets 409. The same bytes again get 204, so a retry after a lost
  answer goes through.
- With the roster the node keeps the descriptors of its peers: it fetches /descriptor from the
  info port of every other roster node (the host of the roster address, the port from
  -peer-info-port, 9100 by default) with a 5 s timeout, a 16 KiB limit on the body and 4 KiB on
  the status line and headers, no redirects and strict decoding, and checks the bundle with
  pki.Verify against the roster's anchor and the roster address. The cache holds public data and
  lives in memory only.
- The node fetches an entry again once its wall-clock age reaches half of its descriptor's
  lifetime. Its timer sleeps until the nearest such moment, at most 1 min and at least 5 s;
  while a peer is missing, or due and not answering, the node asks every 5 s. An entry ends at
  the expires of its descriptor. A bundle that cannot be fetched or does not verify is not
  taken, and the entry held so far stays until it expires. The log gets one line per kind of
  cause: no answer, the status code or the check that failed, and nothing the peer sent. No
  request and no circuit setup triggers a fetch.
- A circuit is extended from this cache alone: the next address must be a roster node with a
  valid entry, and the link to it is authenticated with the link key of that entry. A node with
  -auth extends nowhere until its roster arrives.
- GET /descriptors on the info port is the mirror: the node's own bundle and the cached
  bundles of its roster peers. It is encoded when the cache is refreshed and when the node signs
  its own descriptor; a request copies ready bytes. The answer is 503 until the node holds a
  valid bundle of every roster node, and again from the moment one of them expires.
- A cached bundle may name an onion key its node has already replaced. The node holds that key
  until the bundle has expired (section "Circuit setup", onion key epochs), so a client that
  takes the bundle from the mirror still builds its circuit.
- The mirror makes the entry the only node a client contacts. The client trusts the entry with
  nothing: it verifies every bundle against its own anchor, so the entry can withhold bundles but
  cannot alter them.
- A node run with -auth=false takes no roster. It lists itself in /descriptors under -advertise
  together with the unsigned bundles of the nodes named in -peers, read without verification,
  and extends circuits to any address. Without -advertise it answers /descriptors with 503 and
  names the two flags.
- scripts/e2e.sh checks that clients ask the entry alone. It waits until two passes in a row
  show every node with both peers and relay-2 and relay-3 with unchanged counts, then runs the
  clients. It requires that relay-1 has answered more requests for the mirror after client-a
  and again after the client with the foreign anchor, that mirror_requests of relay-2 and
  relay-3 is still 0 and that their descriptor_requests has not changed.

### Key lifetime and revocation

| Key | Created by | Held in | Lives |
|---|---|---|---|
| CA key | `jimichi enroll`, pki.NewCA, after every request has passed | secmem of the enroll process | the issuance only; Close releases it on every exit path |
| Anchor | the same process | stdout, ConfigMap, client environment | until the next issuance, public |
| Node signing key | cmd/relay at start, before any port opens | secmem; a node told to lock memory does not start without the lock | until the process ends |
| Link key | cmd/relay at start, GenerateEphemeral | secmem | until the process ends; with -onion-rotate 0 it is the onion key as well |
| Onion key | cmd/relay at start and at every rotation, GenerateEphemeral | secmem; with memory locking on, a key that is not locked is not taken | with -onion-rotate one period as the published key and the grace period after it, 1 h 22 min at most on the testbed; released at the end of the grace period and when the process ends |
| Certificate, descriptor | CA, node | node heap, public; the bundle is kept encoded | certificate until not_after or the node restarts; descriptor 1 h by default (-descriptor-ttl), 20 min on the testbed |
| Roster, peer descriptors | enroll, the other nodes | node heap, public | the roster until the node restarts; a peer descriptor until its expires |

- A node restart gives a new signing key, no certificate and no roster. The node is ready
  (readiness on /healthz), but /descriptor and /descriptors answer 503, it extends no circuit,
  and clients refuse to build a circuit through it until scripts/enroll.sh runs. make deploy,
  make start and scripts/e2e.sh run it themselves.
- A new issuance needs fresh node processes. scripts/redeploy.sh restarts the nodes itself, make
  start after make stop brings them up anew, while running make deploy again, make start without
  make stop or scripts/e2e.sh on certified nodes stops with a restart hint. Certificates of the
  previous CA die when the nodes restart with new identities and the clients with the new anchor:
  revocation by forgetting. There is no other revocation.
- The certificate lifetime comes from -cert-ttl: 72 h on the testbed, 1 h in CI.
- The descriptor is signed when the certificate is installed, at every rotation of the onion key
  and otherwise only by the timer; a /descriptor request serves the ready bundle and never
  triggers a signature. The timer fires
  every min(ttl/4, 1 min) and signs again once the descriptor's wall-clock age reaches half its
  lifetime or the certificate state changes. The wall clock matters because the timer runs on
  the monotonic clock, which stands still while the host sleeps.
- After the descriptor's expires or the certificate's not_after the node answers 503. A node
  whose certificate expired comes back only through a restart and a new issuance.

### CA compromise

The CA key takes no part in key agreement. Whoever holds it, that is the operator or someone who
stole the key during the issuance, can certify an identity of their own for any name and address
and, with a position in the network, substitute a node. It gives no layer keys of past circuits:
those come from the nodes' agreement keys, which the CA never sees.

## What is recorded during measurements

| Source | Data |
|---|---|
| client | send and receive timestamps per cell, losses, flow identifier; at start the fingerprint and validity of every verified node |
| relay | aggregated counters on stdout once a minute and on loopback on request: accepted, forwarded, delivered, dropped, padding, closed circuits, refusals by limit, setups refused for an address outside the roster (refused_extend), setups whose next node did not finish the link handshake (failed_extend), expired deadlines, expired circuits, accept retries, state of the installed certificate (cert: none, valid, expired), roster size and peers with a valid cached descriptor (roster, peers), requests answered on the info port for the node's descriptor and for the mirror (descriptor_requests, mirror_requests), the epoch of the onion key and the failed attempts to rotate it (onion_epoch, onion_rotate_failed). No flow identifiers or addresses. The counters are not published on the network: polled often, they would show which ticks carried a real cell. At start the fingerprint and the full hash of the signing key (identity=, identity_hash=), on certificate installation a line with the serial number and not_after, on roster installation a line with the number of nodes and ca_id, on every rotation of the onion key a line with the new epoch and no key material, and one line per kind of cause, naming the peer by its roster address and carrying nothing the peer sent, when a peer's descriptor cannot be fetched or verified |
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
| wire | cell format, layers, counter order | crypto, crypto/secmem |
| link | link encryption between neighbours, frames of one size | crypto, crypto/secmem, wire |
| pki | certificate, descriptor and request of a node, roster and mirror formats, issuing and checking | crypto, crypto/secmem, wire |
| internal/fetch | reading bundles and the mirror from an info port | pki |
| relay | relay node, sending on its own clock | crypto, crypto/secmem, link, wire |
| client | send, receive, cover traffic | crypto, crypto/secmem, link, wire |
| vault | container with two volumes | crypto, crypto/secmem |
| lab/* | scenarios, observer, metrics, reports | client, relay, link, crypto/suite |
| web | testbed dashboard | lab |
| cmd/relay, cmd/client, cmd/lab | entry points and configuration | the packages above |
| cmd/jimichi | testbed CLI: certificate issuance | pki, crypto/suite, crypto/secmem |

Rule: relay, client, wire and cmd/jimichi know nothing about lab. The experiment harness depends
on the system, not the other way round.

## Deployment

- deploy/kind: kind cluster configurations, cluster.yaml for the testbed (a control plane and two
  workers) and ci.yaml for CI (a single node).
- deploy/base: the jimichi namespace, three relays with their Services and the client client-a.
  There are no volumes, the root filesystem is read-only, the user is 65532, seccomp is
  RuntimeDefault and every capability is dropped; relays keep only IPC_LOCK for mlock.
- The manifests hold no Secret at all: node keys are created in process memory and never leave
  it. The only thing that enters the cluster is the public anchor, in ConfigMap jimichi-ca.
- The CA runs outside the cluster: `jimichi enroll` (cmd/jimichi) through scripts/enroll.sh on the
  operator's machine or the CI runner.
- Nodes are deployed with the Recreate strategy, so each Deployment has exactly one live pod and
  issuance finds exactly that one. The -name and -advertise flags set the name and address in the
  certificate, and the address is the one the client knows.
- The relays run with -onion-rotate 1h and -descriptor-ttl 20m: the grace period is 22 min, so
  a node holds a single onion key for the other 38 minutes of every hour.
- deploy/base/network.yaml: a network policy lets each cell port take connections only from the
  hop before it; the info port stays open to the namespace, and the port-forward that issuance
  and the counters use does not pass through it.
- Each relay Service exposes the cell port 9000 and the info port 9100. A client uses both ports
  of its entry only; nodes use the info port of every roster node for the peer descriptors and
  the cell port of the next node of a circuit.
