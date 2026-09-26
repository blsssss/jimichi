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
2. It agrees an ephemeral session key with each node separately. The node proves its identity with
   a signature the client checks against the testbed CA.
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
  bytes for a message.
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
- Two keys are derived from the secret: one for the control cell, one for data cells.
- The control cell is nested like a data cell: the layer of each node holds its ephemeral public
  key, the address of the next node, the identifier of the next link and the layer for the next
  node.
- The hop index travels in the counter field: a node must know its position before it can tell how
  much of the body belongs to its layer.
- After stripping its layer a node refills the cell to 512 bytes and forwards it.

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

- Every node has a long-term signing pair and a certificate from the testbed CA.
- The CA is run by lab, lives outside the cluster and exists only for the testbed.
- The client checks the node's signature during key agreement. A compromised CA does not expose
  the content of past sessions: the CA key takes no part in the layer agreement, and the client
  picks the chain.

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
| relay | relay node, sending on its own clock | crypto, crypto/secmem, link, wire |
| client | send, receive, cover traffic | crypto, crypto/secmem, link, wire |
| vault | container with two volumes | crypto, crypto/secmem |
| lab/* | scenarios, observer, metrics, reports | client, relay, link, crypto/c25519 |
| web | testbed dashboard | lab |
| cmd/relay, cmd/client, cmd/lab | entry points and configuration | the packages above |

Rule: relay, client and wire know nothing about lab. The experiment harness depends on the system,
not the other way round.

## Deployment

- deploy/compose: docker-compose with three relays and two clients, the development mode.
- deploy/kind and deploy/base: the same set in a Kubernetes cluster, for the defence demo.
  The manifests hold no Secret with keys, volumes are tmpfs in RAM, the root filesystem is
  read-only.
