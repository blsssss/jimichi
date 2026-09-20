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
5. Session keys live until the circuit is torn down and are then zeroed.

## Cell format

Every cell is 512 bytes, payload and cover cells alike.

| Field | Size | Purpose |
|---|---|---|
| version | 1 | format version |
| kind | 1 | payload, cover, control |
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
- Inside the innermost layer: two bytes of length, the data, random padding. Three hops leave 444
  bytes for a message.
- A node keeps a window of accepted counters and drops a replay: forwarding one would hand an
  active observer a free timing mark.

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

## Node authentication

- Every node has a long-term signing pair and a certificate from the testbed CA.
- The CA is run by lab, lives outside the cluster and exists only for the testbed.
- The client checks the node's signature during key agreement. A compromised CA does not expose
  the content of past sessions: layers are encrypted with ephemeral keys and the client picks the
  chain.

## What is recorded during measurements

| Source | Data |
|---|---|
| client | send and receive timestamps per cell, losses, flow identifier |
| relay | aggregated counters on stdout: accepted, forwarded, dropped. No flow identifiers |
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
| crypto/secmem | key memory | x/sys/unix |
| crypto/providertest | contract conformance tests | crypto |
| wire | cell format, layers, replay window | crypto |
| relay | relay node | crypto, wire |
| client | send, receive, cover traffic | crypto, wire |
| vault | container with two volumes | crypto, crypto/secmem |
| lab/* | scenarios, observer, metrics, reports | client, relay, wire |
| web | testbed dashboard | lab |
| cmd/* | entry points and configuration | the packages above |

Rule: relay, client and wire know nothing about lab. The experiment harness depends on the system,
not the other way round.

## Deployment

- deploy/compose: docker-compose with three relays and two clients, the development mode.
- deploy/kind and deploy/base: the same set in a Kubernetes cluster, for the defence demo.
  The manifests hold no Secret with keys, volumes are tmpfs in RAM, the root filesystem is
  read-only.
