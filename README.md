<p align="center">
  <img src="docs/img/logo.png" width="96" alt="jimichi">
</p>

<h1 align="center">jimichi</h1>

<p align="center">
  Confidential messaging that hides who talks to whom, and the measurements of what that
  protection is worth.
  <br>
  <a href="https://jimichi.org">jimichi.org</a> · English | <a href="README.ru.md">Русский</a>
</p>

<p align="center">
  <a href="https://github.com/jimichi-org/jimichi/actions/workflows/ci.yml"><img src="https://github.com/jimichi-org/jimichi/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/jimichi-org/jimichi"><img src="https://api.scorecard.dev/projects/github.com/jimichi-org/jimichi/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://doi.org/10.5281/zenodo.23001699"><img src="https://zenodo.org/badge/DOI/10.5281/zenodo.23001699.svg" alt="DOI"></a>
</p>

A confidential messaging system that protects metadata, and the measurements that show what
that protection is worth.

Messages travel through a chain of three relay nodes under nested encryption: the client draws
the chain at random from the nodes it lists, every hop strips exactly one layer and learns only
its neighbours. The recipient client and the end-to-end encryption layer are planned
([#18](https://github.com/jimichi-org/jimichi/issues/18)): today the last node of the chain reads
the message and echoes it back.

Session keys are ephemeral, the buffers that hold them sit in mlocked memory outside the Go heap
and are zeroed after use, and a node writes nothing to disk itself. Only these buffers are locked
against swap; locking all process memory is planned
([#36](https://github.com/jimichi-org/jimichi/issues/36)). Copies that the crypto libraries keep
on the heap are not covered, see [LIMITATIONS](docs/en/LIMITATIONS.md). Every cell is the same
size, so a message that fits in one cell does not show its length on the wire. A longer message
is refused with an error and not sent: fragmentation and size classes are planned
([#68](https://github.com/jimichi-org/jimichi/issues/68)).

Protecting content is the easy part. What this work measures is the harder question: how much
an observer who sees only timings and volumes can still learn, and what it costs to take that
away. The repository therefore contains both the system and the attack against it.

## What is measured

- **Key material.** Planned ([#24](https://github.com/jimichi-org/jimichi/issues/24)): memory
  dumps of a live relay will be searched for known key bytes, with and without memory locking and
  dump prevention, and the same search will run against the container image and the node's files.
  The switches that start a node without each measure exist today (`-keymem`, `-harden`).
- **Forward secrecy.** Planned ([#24](https://github.com/jimichi-org/jimichi/issues/24)): setup
  cells recorded by a neighbour will be attacked with the keys taken from node memory, by the age
  of the recording. Today unit tests check that a setup cell stops opening once the node releases
  the onion key it was built for.
- **Metadata.** A traffic correlation attack links the flows on the entry link to the flows on
  the last link between relays from cell timings and counts alone; AUC, top-1 accuracy and TPR at
  FPR 0.01 are reported against cover traffic rate, a constant client rate and relays sending on
  their own clocks. Node delay levels ([#45](https://github.com/jimichi-org/jimichi/issues/45)),
  message size classes ([#68](https://github.com/jimichi-org/jimichi/issues/68)) and the path to a
  recipient ([#47](https://github.com/jimichi-org/jimichi/issues/47)) are planned.
- **Partial compromise.** How often a randomly drawn chain meets rogue nodes is computed and
  sampled with the client's own choice (`cmd/lab -set paths`). What one or two compromised nodes
  of three learn, including a node holding a valid certificate from a compromised CA, is planned
  ([#117](https://github.com/jimichi-org/jimichi/issues/117)).
- **Cost.** Round-trip latency through the chain, the bandwidth multiplier of cover and padding,
  and benchmarks of key agreement, signing and sealing a cell, GOST versus X25519. Node throughput
  at saturation, goodput per client, the cost of a setup while a node holds two onion keys, the
  latency of a one-node chain and the cost of memory locking are planned
  ([#118](https://github.com/jimichi-org/jimichi/issues/118)).

Threat modelling follows the FSTEC methodology of 2021-02-05; scenarios are named in plain words.

## Results

Preliminary series: ten flows, three relays, c25519 suite, five 30 s runs per configuration, each
client starting its schedule at a random phase. Every number is the median across the five runs.
Rows with the client alone come from the series over client rates, rows with relay clocks from
the series over relay periods, whose own client-only runs agree (AUC 0.947 at 70 ms, 0.950 at
35 ms). With five runs per point no difference is claimed as significant; the full series of
thirty runs per point is still to come ([#23](https://github.com/jimichi-org/jimichi/issues/23)).
The lab harness starts the relays and the clients in one process on loopback, not on the kind
testbed described below, so there is no network delay; network emulation is planned
([#46](https://github.com/jimichi-org/jimichi/issues/46)).

A passive observer sees only when frames cross the entry link and the last link between relays. It
counts frames per time window for every flow and correlates every entry flow with every exit flow.
The window is the observer's choice, so both 10 ms and 100 ms are scored and the figure takes the
better one for the observer. Chance is AUC 0.5 and top-1 10%.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/img/tradeoff-en-dark.png">
  <img alt="Attack AUC against bandwidth between relays and against round-trip latency, for cover on top, a constant rate at the client and relays on their own clocks" src="docs/img/tradeoff-en-light.png">
</picture>

| Protection | Bandwidth between relays | Median round trip | AUC, 10 ms | AUC, 100 ms | Top-1, 10 ms |
|---|---|---|---|---|---|
| none | x1.00 | 0.15 ms | 1.000 | 1.000 | 100% |
| cover on top, +2x | x2.99 | 0.13 ms | 1.000 | 1.000 | 100% |
| constant rate at the client, 70 ms | x2.85 | 47 ms | 0.948 | 0.952 | 60% |
| constant rate at the client, 35 ms | x5.69 | 21 ms | 0.951 | 0.942 | 70% |
| relays on their own clocks, 66.5 ms | x3.00 | 182 ms | 0.485 | 0.483 | 0% |
| relays on their own clocks, 33.25 ms | x5.99 | 89 ms | 0.528 | 0.550 | 10% |
| both, client 70 ms, relays 66.5 ms | x2.99 | 216 ms | 0.506 | 0.526 | 15% |
| both, client 35 ms, relays 33.25 ms | x5.99 | 108 ms | 0.596 | 0.486 | 10% |

- Cover traffic added on top of real messages does not help at all: even at three times the
  bandwidth every flow is linked.
- A constant rate at the client does not hide a flow either. Each client ticks with its own phase,
  the phase crosses a chain of relays that forward at once, and with a 10 ms window the attack links
  flows at every rate. A 100 ms window looks safe only where the period divides it: almost every
  window then holds the same number of cells and nearly all scores tie (AUC 0.50-0.55), which says
  nothing about protection. In this series the last client to start ticked in step with the
  observer's windows, a harness effect since removed.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/img/window-en-dark.png">
  <img alt="Attack AUC against the client's cell period for a 10 ms and a 100 ms window" src="docs/img/window-en-light.png">
</picture>

- Relays sending on their own clocks bring this attack, which counts cells only, down to chance.
  The price is a constant stream on every link a relay sends on and about 2.5 to 2.7 node periods
  added to a round trip (182 ms at 66.5 ms, 89 ms at 33.25 ms). The relay period is 5% shorter
  than the client's, so a missed tick is caught up. The moments the connections of a circuit open
  and close match along the chain and are not part of the attack yet
  ([#43](https://github.com/jimichi-org/jimichi/issues/43)).
- The client's constant rate still matters with relay clocks on: it hides the conversation from
  the entry node itself, which the observer here does not model.

Series are run on an idle host; every report row records the host load, the seeds and the code
revision.

## Cryptography

All primitives sit behind a single `CryptoProvider` interface. The default suite is X25519,
XChaCha20-Poly1305 and Ed25519, so results are comparable with international work. A second suite
implements the Russian standards (VKO GOST R 34.10-2012, Kuznyechik-MGM, Streebog) behind the same
contract and is switched on with `-suite gost`; a difference between the two points at the suite,
not at the harness. Both pass the same conformance tests; GOST is also checked against the
known-answer examples of its standards, and c25519 signing against RFC 8032. See [docs/en/CRYPTO.md](docs/en/CRYPTO.md).

## Layout

```
cmd/          entry points: relay, client, jimichi (testbed CLI), lab
crypto/       CryptoProvider interface
  gost/       GOST suite
  c25519/     X25519 / XChaCha20-Poly1305 / Ed25519 suite
  suite/      picks a suite by name
  secmem/     mlocked, non-dumpable, self-zeroing key buffers
  providertest/ conformance suite both suites must pass
wire/         fixed-size cells, nested layers, counter order
link/         link encryption between neighbours, frames of one size
pki/          node certificates, descriptors and requests, issuing and checking
relay/        relay node
client/       choice of the chain, sending, replies from the exit, cover traffic
vault/        client container with two volumes, planned (#20), a placeholder package today
lab/          run harness and observer, metrics/; scenario/ and report/ are placeholders
web/          testbed dashboard, planned (#21), a placeholder package today
deploy/       kind/ cluster configurations and base/ manifests of the testbed
docs/         documentation, en/ and ru/
```

## Documentation

- [docs/en/ARCHITECTURE.md](docs/en/ARCHITECTURE.md) - components, message flow, cell format.
- [docs/en/THREAT_MODEL.md](docs/en/THREAT_MODEL.md) - assets, adversaries, threats, deniability.
- [docs/en/CRYPTO.md](docs/en/CRYPTO.md) - the CryptoProvider contract.
- [docs/en/EXPERIMENT.md](docs/en/EXPERIMENT.md) - adversary models, metrics, experiment blocks.
- [docs/en/LIMITATIONS.md](docs/en/LIMITATIONS.md) - what the results do and do not cover.
- [docs/en/GLOSSARY.md](docs/en/GLOSSARY.md) - terms.

## Running the testbed

```
kind create cluster --config deploy/kind/cluster.yaml
make images
kind load docker-image jimichi/relay:dev jimichi/client:dev --name jimichi
kubectl apply -f deploy/base/relay.yaml -f deploy/base/network.yaml
kubectl -n jimichi wait --for=condition=Available deployment -l app=relay --timeout=180s
bash scripts/enroll.sh
kubectl apply -f deploy/base/client.yaml
```

`make deploy` runs the last four steps. Five relays and a client appear in the `jimichi`
namespace. A relay creates its signing key in memory at start and waits for enrollment:
`scripts/enroll.sh` builds `cmd/jimichi` and runs `jimichi enroll` on the host, which certifies
every relay through a port-forward under a CA that exists only for that run, gives each relay the
roster of the certified nodes and stores the CA public key, the anchor, in ConfigMap `jimichi-ca`.
The relay then publishes a signed descriptor on port 9100, keeps the verified descriptors of the
other roster nodes and extends circuits only to them over authenticated links. After a relay
restarts, every relay has to be restarted and enrolled again, since a process takes one
certificate and one roster: `kubectl -n jimichi rollout restart deployment -l app=relay`, then
`make enroll`.

The client lists all five relays and builds a chain of three (`-hops`). At every start it draws
its entry at random, asks that entry for the signed bundles of every listed node, verifies each
bundle it gets against the anchor and only then draws the other two hops among the verified nodes.
The entry may leave out one listed node (`-missing`, 1 by default), which lets a rogue entry narrow
the choice ([LIMITATIONS](docs/en/LIMITATIONS.md)). The client does not log the chain, and after
any failure it exits and draws a new one at its next start. `-fixed-chain` keeps the listed order
for measurements that need a known path.

Aggregated counters go to stdout once a minute and to port 9101 on loopback only, read through a
port-forward:

```
kubectl -n jimichi port-forward deployment/relay-3 9101:9101
curl -s localhost:9101/stats
```

## Requirements

Go 1.27. Memory locking and dump prevention are Linux-only, and so will be the planned
key-extraction scenarios ([#24](https://github.com/jimichi-org/jimichi/issues/24)); other
platforms build against stubs that report memory as unlocked, so a node refuses to start there.
Docker and kind for the testbed; a Compose setup for development is planned
([#22](https://github.com/jimichi-org/jimichi/issues/22)).

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
