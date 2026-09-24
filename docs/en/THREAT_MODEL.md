# Threat model

English | [Русский](../ru/THREAT_MODEL.md)

Built along the FSTEC methodology for assessing information security threats of 2021-02-05, with
typical threats checked against the FSTEC threat database. Written in plain words, without codes:
this is engineering work, not a certification exercise.

## What is protected

| Asset | Where it lives | What compromise costs |
|---|---|---|
| Session keys of the layers | memory of the relay process | confidentiality of messages passing that node |
| Long-term node key | memory of the relay process, a file when issued | the ability to impersonate the node |
| The link between sender and recipient | timings and volumes, node state | confidentiality of the fact of communication |
| Message content | cells on the network | confidentiality of the conversation |

## Adversaries

| Adversary | Capability | What is available |
|---|---|---|
| Passive network observer | sees traffic at the entry and the exit of the chain | timings, volumes, packet sizes |
| Active network observer | additionally delays, duplicates and modifies cells | attempts at replay and tampering |
| Operator of one node | full access to their own node, including memory | one layer, the addresses of the neighbours |
| Runtime administrator | root on the machine hosting a node, reads any process memory | node memory, including keys while they exist |
| Certificate authority owner | issues valid certificates | inserting their own node into a chain |

The adversary knows the design and the source code. Security rests on keys, not on the secrecy of
the implementation.

## Threats and countermeasures

| Threat | Countermeasure | How it is checked |
|---|---|---|
| Reading keys from node memory | keys in mlocked memory, dumps and ptrace disabled, zeroing after use | searching for the key in a process dump, with and without the measure |
| Keys reaching disk or swap | the node writes nothing, pages are locked, volumes are tmpfs | searching for the key in the container image, dumps and node files |
| Past sessions exposed after a long-term key is stolen | ephemeral session keys, the long-term key only signs | attempting to decrypt recorded traffic with the long-term key at hand |
| Linking sender and recipient by traffic | constant cell size, cover traffic, delays and batching | our own correlation attack, ROC and AUC under different parameters |
| One node learning the whole route | nested encryption, a node sees only its neighbours | compromising one node of three, checking what it holds |
| A node inserted through a compromised CA | the client picks the chain, layers are encrypted per node | inserting one and two nodes, measuring the residual leak |
| Linking a flow by cell headers | link encryption between neighbours, frames of one size on the wire | searching a link capture for counters and identifiers |
| Replay and tampering | AEAD on every layer, a window of counters | replaying a recorded cell, flipping a byte, expecting a refusal |
| Proving that a message was sent | cover and payload cells are indistinguishable on the wire | distinguishing the two kinds from observable features, expecting chance level |
| Proving authorship to a third party | deniable authentication: the recipient is convinced by a shared secret, not by a signature | the recipient forges a transcript indistinguishable from a real one |
| Coercion after the session | ephemeral keys are zeroed, no keys on disk | searching memory and disk for the key after the session ends |

## Deniability: what is claimed and what is not

Three properties are claimed, each of them measured:

- Deniability of sending: an observer cannot tell a cell carrying a message from a cover cell, so
  it cannot prove that the user sent anything at that moment.
- Deniable authentication: the recipient is sure of the author but cannot prove authorship to a
  third party, because it can produce the same transcript itself.
- Nothing to surrender after the session: keys are ephemeral and zeroed, and none reach disk.

Not claimed: hidden volumes and a second bottom in storage. Such schemes fall to an adversary
holding several snapshots of the state over time and give no verifiable guarantee. The nodes store
nothing at all, so the property is not needed there.

## Out of scope

- Compromise of the user's device and client.
- A global observer seeing all traffic of all participants at once.
- Side-channel attacks on the primitive implementations.
- Denial of service: a node can be stopped, that is neither hidden nor measured.
- Analysis requiring long-term statistics on real users: the testbed dataset is synthetic.
