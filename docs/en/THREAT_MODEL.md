# Threat model

English | [Русский](../ru/THREAT_MODEL.md)

Built along the FSTEC methodology for assessing information security threats of 2021-02-05, with
typical threats checked against the FSTEC threat database. Written in plain words, without codes:
this is engineering work, not a certification exercise.

## What is protected

| Asset | Where it lives | What compromise costs |
|---|---|---|
| Session keys of the layers | memory of the relay process | confidentiality of messages passing that node |
| Node signing key | memory of the relay process (secmem), until the node restarts | the ability to impersonate the node until the certificate's not_after or the node restarts |
| Node onion key (agreement key) | memory of the relay process (secmem); with rotation one period as the published key and the grace period after it, without rotation until the node restarts | the layers of circuits set up under that key, for whoever kept their setup cells |
| Node link key | memory of the relay process (secmem), until the node restarts | the ability to answer a link in place of the node until it restarts; no layer and no recorded link opens with it. Without rotation it is the onion key as well |
| CA key | memory of the jimichi enroll process outside the cluster, only while it issues certificates | issuing certificates for any name and address until the anchor changes |
| Trust anchor (integrity) | ConfigMap jimichi-ca, client environment | a substituted anchor makes the client accept nodes of another CA |
| The link between sender and recipient | timings and volumes, node state | confidentiality of the fact of communication |
| Message content | cells on the network; the memory of the exit, which opens the last layer and reads the message: the end-to-end layer is planned ([#18](https://github.com/jimichi-org/jimichi/issues/18)) | confidentiality of the conversation |

## Adversaries

| Adversary | Capability | What is available |
|---|---|---|
| Passive network observer | sees traffic at the entry and the exit of the chain | timings, volumes, packet sizes |
| Active network observer | additionally delays, duplicates and modifies cells, answers a connection in place of a node | attempts at replay and tampering, at taking the place of a node |
| Operator of one node | full access to their own node, including memory | one layer, the addresses of the neighbours; at the exit also the message itself and the cover flag: the end-to-end layer is planned ([#18](https://github.com/jimichi-org/jimichi/issues/18)) |
| Runtime administrator | root on the machine hosting a node, reads any process memory | node memory, including keys while they exist |
| Certificate authority owner | the operator who runs issuance, or whoever stole the CA key during issuance; issues valid certificates | a certificate for an identity of their own for any name and address, with a network position inserting their own node into a chain |

The adversary knows the design and the source code. Security rests on keys, not on the secrecy of
the implementation.

## Threats and countermeasures

| Threat | Countermeasure | How it is checked | Status |
|---|---|---|---|
| Reading keys from node memory | key buffers off the heap under mlock, dumps and ptrace disabled, zeroing after use. Copies the libraries keep on the heap are not covered (CRYPTO, known gaps) | secmem tests: the kernel marks the key pages as locked and excluded from dumps. Planned ([#24](https://github.com/jimichi-org/jimichi/issues/24)): searching for the key in a process dump, with and without the measure | partly: the dump search is not implemented ([#24](https://github.com/jimichi-org/jimichi/issues/24)) |
| Keys reaching disk or swap | the node writes nothing to disk; on the testbed its root filesystem is read-only and its manifest declares no volumes. Key buffers are locked with mlock, which keeps them out of swap. The copies libraries keep on the heap are not locked and can reach swap (CRYPTO, known gaps); locking all process memory is planned ([#36](https://github.com/jimichi-org/jimichi/issues/36)) | secmem tests: the kernel marks the key pages as locked. Planned ([#24](https://github.com/jimichi-org/jimichi/issues/24)): searching for the key in the container image, dumps and node files | partly: only the key buffers are locked ([#36](https://github.com/jimichi-org/jimichi/issues/36)), the search is not implemented ([#24](https://github.com/jimichi-org/jimichi/issues/24)) |
| Past sessions exposed after node keys are stolen | links between neighbours run on ephemeral keys, so a capture from the wire cannot be read without them. The onion key, which takes part in the layer agreement, changes by epochs (-onion-rotate), and a replaced key is released after the grace period: a setup cell kept by a neighbour opens only while its key is held, at most the rotation period plus the descriptor lifetime plus the clock allowance after the key was first published, counted by the wall clock and by the running time of the host, whichever ends first (LIMITATIONS). What remains: the hop keys of circuits that are alive when memory is taken; heap copies the libraries left of a released onion key, of setup secrets and of the hop keys of circuits already torn down, until that memory is reused (CRYPTO, known gaps); a node that cannot act, asleep or unable to make its next key; and a node without rotation, whose key lives until it restarts. The node signing key and the CA key take no part in the agreement | relay tests: a setup for a replaced key opens during the grace period and is refused after the release. Planned ([#24](https://github.com/jimichi-org/jimichi/issues/24)): attempting to open recorded setup cells with the keys found in node memory, by the age of the recording | partly: the test with keys taken from node memory is not implemented ([#24](https://github.com/jimichi-org/jimichi/issues/24)) |
| Linking sender and recipient by traffic | constant cell size, cover traffic, a constant rate at the client (-mode fixed), a random delay before each cell at the client (-jitter), sending on the node's own clock (-period). Random delays and batching at nodes are planned ([#45](https://github.com/jimichi-org/jimichi/issues/45), [#82](https://github.com/jimichi-org/jimichi/issues/82)) | our own correlation attack between the entry link and the last link between nodes: AUC, TPR at FPR 0.01 and top-1 under different parameters. There is no recipient yet, the end-to-end path is planned ([#18](https://github.com/jimichi-org/jimichi/issues/18), [#47](https://github.com/jimichi-org/jimichi/issues/47)) | partly: no random delays or batching at nodes ([#45](https://github.com/jimichi-org/jimichi/issues/45), [#82](https://github.com/jimichi-org/jimichi/issues/82)) |
| One node learning the whole route | nested encryption; a node sees only its neighbours: the client connects to its entry alone and asks it for the bundles of every listed node, so the request does not show the chain, and for a circuit a node connects only to the next node. Not covered: a node can serve a different validly signed onion key to each of the others, and the key that opens a setup cell then tells it whose mirror the client used, so a rogue exit can learn the entry (LIMITATIONS) | e2e: per start of a client one relay answers a request for the mirror, and no relay a request for its own descriptor; wire and relay tests: one cell carries a different counter on every link, and a node before the exit sees the same header on a cover and a payload cell. Planned ([#117](https://github.com/jimichi-org/jimichi/issues/117)): compromising one node of a chain in the lab and checking what it holds (EXPERIMENT, block 3) | partly: the node compromise scenario is not implemented ([#117](https://github.com/jimichi-org/jimichi/issues/117)) |
| Node keys substituted when fetched | the signed descriptor: the client takes keys only from a bundle verified against the anchor and refuses to build the circuit on any error; the entry that serves the bundles can withhold them but cannot alter them | e2e: a client holding the anchor of another CA refuses to build the circuit; pki and client tests for every refusal | implemented |
| An active party between nodes takes the place of the next node | every link of a circuit is authenticated with the link key from the verified descriptor of the node it leads to; a node extends a circuit only to the nodes of its roster | relay tests: a setup naming an address outside the roster is refused without a connection; a responder without the expected link key fails the handshake and is sent no setup cell | implemented |
| A node inserted through a compromised CA | the CA key lives outside the cluster and only while it issues certificates; the client draws the chain uniformly among its N listed nodes, so k rogue nodes hold both ends of a chain with probability k(k-1)/(N(N-1)) and some node of a chain of h nodes with 1 - C(N-k,h)/C(N,h), 0.1 and 0.9 for two rogue nodes of five and chains of three when the entry leaves no node out of its mirror (2/15 for both ends when a rogue entry leaves out one honest node, LIMITATIONS); layers are encrypted per node | chains sampled with the client's own choice against these values (EXPERIMENT, block 3). Planned ([#117](https://github.com/jimichi-org/jimichi/issues/117)): inserting one and two nodes, measuring the residual leak | partly: the measurement with inserted nodes is not implemented ([#117](https://github.com/jimichi-org/jimichi/issues/117)) |
| The chain revealed or steered by the node that serves the descriptors | the entry is asked for the bundles of every listed node whatever the chain, every one of them is verified, the other hops are drawn after that from the system generator, and the client logs no node of the chain; the entry can withhold the mirror, and the client then exits and draws another entry, or leave out at most -missing listed nodes, which bounds how far it steers the choice; a node that withholds its descriptor from the others only removes itself from their mirrors | client tests: for one mirror the request and the log are the same whatever chain is drawn, a node off the chain that fails the check refuses the circuit | implemented |
| Linking a flow by cell headers | link encryption between neighbours, frames of one size on the wire; an identifier and a counter of its own on every link, counters strictly in turn | link tests: a capture of a link holds neither the counter nor the identifier of the cell it carried; wire and relay tests: one cell carries a different counter on every link, in both directions | implemented |
| Replay and tampering | AEAD on every layer, counters strictly in turn on every link (a copy, a gap or a reorder closes the circuit), tags of opened control cells for as long as the onion key that opened them is held | replaying a recorded cell, flipping a byte, expecting a refusal | implemented |
| Proving that a message was sent | cover and payload cells have the same size and header for every node before the exit, and the frames on the wire are of one size: the cover flag sits inside the innermost layer. The moment of sending is hidden only at a constant rate (-mode fixed, set on the testbed): in the immediate mode, the default of the client, a cell leaves when the user sends, and without -cover every data cell is a message | wire and relay tests: a node before the exit sees the same header on a cover and a payload cell, and the exit answers each with one cell. Planned ([#119](https://github.com/jimichi-org/jimichi/issues/119)): distinguishing the two kinds from observable features, expecting chance level | partly: the distinguisher is not implemented ([#119](https://github.com/jimichi-org/jimichi/issues/119)), the moment of sending is hidden only at a constant rate |
| Proving authorship to a third party | planned: deniable authentication, where the recipient is convinced by a shared secret, not by a signature. There is no recipient client and no authentication between clients yet ([#18](https://github.com/jimichi-org/jimichi/issues/18), [#19](https://github.com/jimichi-org/jimichi/issues/19)) | planned: a demonstration that the recipient can forge the conversation, a transcript it can produce itself | planned ([#19](https://github.com/jimichi-org/jimichi/issues/19)) |
| Coercion after the session | ephemeral key buffers are zeroed, the node writes no key to disk; library copies on the heap live until the memory is reused and are not locked against swap ([#36](https://github.com/jimichi-org/jimichi/issues/36)) | relay tests: a node holds no cipher of a circuit once it is closed. Planned ([#24](https://github.com/jimichi-org/jimichi/issues/24)): searching memory and disk for the key after the session ends | partly: the search after a session is not implemented ([#24](https://github.com/jimichi-org/jimichi/issues/24)) |

## Deniability: what is claimed and what is not

Three properties are claimed: two are implemented within the limits named below, deniable
authentication is planned. None of them is measured yet, the measurements are planned:

- Deniability of sending: an observer cannot tell a cell carrying a message from a cover cell, so
  it cannot prove that the user sent anything at that moment. This holds when the client sends at
  a constant rate (-mode fixed): in the immediate mode, the default, a cell leaves when the user
  sends, and without -cover every data cell is a message. The distinguisher that will measure the
  property is planned ([#119](https://github.com/jimichi-org/jimichi/issues/119)).
- Deniable authentication, planned ([#19](https://github.com/jimichi-org/jimichi/issues/19))
  together with the recipient client ([#18](https://github.com/jimichi-org/jimichi/issues/18)):
  the recipient will be sure of the author but unable to prove authorship to a third party,
  because it will be able to produce the same transcript itself.
- Nothing to surrender after the session: keys are ephemeral, their buffers are zeroed, and a node
  writes no key to disk. The copies libraries leave on the heap are not locked and on a host with
  swap can be paged out to disk before that memory is reused (LIMITATIONS). How long those copies
  survive is to be measured, not assumed ([#24](https://github.com/jimichi-org/jimichi/issues/24));
  locking all process memory is planned ([#36](https://github.com/jimichi-org/jimichi/issues/36)).

Not claimed: hidden volumes and a second bottom in storage. Such schemes fall to an adversary
holding several snapshots of the state over time and give no verifiable guarantee. The nodes store
nothing at all, so the property is not needed there. The client stores nothing either for now: its
container with two volumes is planned ([#20](https://github.com/jimichi-org/jimichi/issues/20)),
and LIMITATIONS states where the deniability of such a container ends.

## Out of scope

- Compromise of the user's device and client.
- A global observer seeing all traffic of all participants at once.
- Side-channel attacks on the primitive implementations.
- Denial of service beyond the node limits: a node gives one address at most its share of links,
  handshakes and setups and bounds the life of circuits (ARCHITECTURE, node limits; the numbers
  are in LIMITATIONS). Every node keeps the per-address limits, since any node can be an entry;
  the circuits a node forwards share one address's allowance at the next node. On the testbed a
  cell port takes connections from client and relay pods only (where the network plugin enforces
  network policies). Load from enough addresses to fill the global caps, filling the setup-tag
  cache of an onion key (about 91 hours from one address, about 90 addresses within one rotation
  period of the testbed), a node that refuses the circuits it does not like, and stopping a node
  are neither prevented nor measured.
- Analysis requiring long-term statistics on real users: the testbed dataset is synthetic.
