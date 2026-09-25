<p align="center">
  <img src="docs/img/logo.png" width="96" alt="jimichi">
</p>

<h1 align="center">jimichi</h1>

<p align="center">
  Confidential messaging that hides who talks to whom, and the measurements that prove it.
  <br>
  English | <a href="README.ru.md">Русский</a>
</p>

A confidential messaging system that protects metadata, and the measurements that show what
that protection is worth.

Messages travel through a chain of three relay nodes under nested encryption: every hop strips
exactly one layer and learns only its neighbours. Session keys are ephemeral, live in mlocked
memory outside the Go heap, are zeroed after use, and never reach disk or swap. Every cell is
the same size, so the length of a message says nothing about it.

Protecting content is the easy part. What this work measures is the harder question: how much
an observer who sees only timings and volumes can still learn, and what it costs to take that
away. The repository therefore contains both the system and the attack against it.

## What is measured

- **Key material.** Memory dumps of a live relay are searched for known key bytes, with and
  without memory locking and dump prevention; the same search runs against the container image
  and volumes.
- **Forward secrecy.** Recorded traffic is attacked with the node's long-term key in hand.
- **Metadata.** A traffic correlation attack links senders to receivers from timings and volumes
  alone; its ROC and AUC are reported against cover traffic rate, cell size policy and delays.
- **Partial compromise.** One and two nodes of three are compromised, including a node holding a
  valid certificate from a compromised CA; residual leakage is measured.
- **Cost.** Latency per hop, throughput, CPU, padding overhead, GOST versus X25519.

Threat modelling follows the FSTEC methodology of 2021-02-05; scenarios are named in plain words.

## Results

Preliminary: ten flows, three relays. The 100 ms column is the median of three 30 s runs. Every
other column, including the no-cover row, comes from one 20 s run, except the cover row, which is
the median of three 30 s runs and counts a few cells sent just after the window (under 1% more
bandwidth). The full series of thirty runs per point is still to come.

A passive observer sees only when frames cross the entry link and the last link before the exit.
It counts frames per time window for every flow and correlates every entry flow with every exit
flow. The window size is the observer's choice.

| Traffic | Bandwidth | Median latency | AUC, 100 ms window | AUC, 10 ms window | Top-1, 10 ms |
|---|---|---|---|---|---|
| no cover | x1.01 | 0.13 ms | 1.000 | 1.000 | 100% |
| cover added on top, x2 | x2.02 | 0.14 ms | 1.000 | not needed | 100% at 100 ms |
| constant rate, 5 cells/s | x0.97 | 979 ms | 0.500 | 0.684 | 20% |
| constant rate, 7 cells/s | x1.38 | 192 ms | 0.500 | 0.658 | 30% |
| constant rate, 10 cells/s | x1.93 | 83 ms | 0.500 | 0.669 | 30% |
| constant rate, 14 cells/s | x2.77 | 50 ms | 0.720 | 0.684 | 20% |
| constant rate, 20 cells/s | x3.87 | 32 ms | 0.500 | 0.704 | 20% |
| constant rate, 29 cells/s | x5.53 | 20 ms | 0.89 | 0.928 | 50% |
| constant rate, 40 cells/s | x7.74 | 14 ms | 0.500 | 0.878 | 40% |

Chance is AUC 0.5 and top-1 10%. At 5 cells/s the schedule is no faster than the messages, so the
queue keeps growing: the multiplier is below one and the latency depends on how long the run lasts.

- Cover traffic added on top of real messages does not help at all: every flow is still linked.
- A constant sending rate at the client hides a flow only when, at the observer's window, every
  flow looks exactly the same: either each window holds the same number of cells (the window is a
  multiple of the period) or all clients happen to tick in phase and give the same pattern. Then
  every score ties. With a 10 ms window the schedule itself becomes the fingerprint: each client
  ticks with its own phase, the phase survives the chain, and the attack links flows well above
  chance at every rate.
- The next measure follows from this: every relay has to send on its own clock, so that the
  client's phase does not reach the exit.

Series are run on an idle host: individual runs taken while the machine was busy scored lower.

## Cryptography

All primitives sit behind a single `CryptoProvider` interface. The primary suite is GOST
(VKO GOST R 34.10-2012, Kuznyechik-MGM, Streebog); a second suite (X25519, XChaCha20-Poly1305,
Ed25519) implements the same contract, so results are comparable with international work and a
difference points at the suite, not at the harness. Both must pass the same conformance tests.
See [docs/en/CRYPTO.md](docs/en/CRYPTO.md).

## Layout

```
cmd/          entry points: relay, client, jimichi
crypto/       CryptoProvider interface
  gost/       GOST suite
  c25519/     X25519 / XChaCha20-Poly1305 / Ed25519 suite
  secmem/     mlocked, non-dumpable, self-zeroing key buffers
  providertest/ conformance suite both suites must pass
wire/         fixed-size cells, nested layers, replay window
relay/        relay node
client/       sender, receiver, cover traffic
vault/        client container with two volumes
lab/          scenario/, metrics/, report/
web/          testbed dashboard
deploy/       compose/ for development, kind/ and base/ for the demo
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
kubectl apply -f deploy/base/relay.yaml
kubectl apply -f deploy/base/client.yaml
```

Three relays and a client appear in the `jimichi` namespace. A relay publishes its public key on
port 9100. Its aggregated counters go to stdout once a minute and to port 9101 on loopback only,
read through a port-forward:

```
kubectl -n jimichi port-forward deployment/relay-3 9101:9101
curl -s localhost:9101/stats
```

## Requirements

Go 1.27. Memory locking, dump prevention and the key-extraction scenarios are Linux-only; other
platforms build against stubs that report memory as unlocked, so a node refuses to start there.
Docker Compose for development, kind for the cluster demo.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
