# Research programme

English | [Русский](../ru/EXPERIMENT.md)

The work answers one question: **what does resistance to traffic analysis cost in bandwidth and
latency in a three-hop chain with constant-size cells, and where does that resistance stop
working**. Everything else serves that answer.

Every run is reproducible: the configuration, the generator seed, the code version and the time
go into the report. Results live in artifacts/ and the figures are produced from those files.

Real clients start at unrelated moments, so on the testbed each client's schedule gets a random
phase drawn from the run's seed. Clients started back to back would tick almost in phase and hand
the attack ties that a real network does not produce. The observation window also opens at a
random moment relative to the schedules; otherwise the last client to start would tick in step with
the windows.

Seeds: each repeat's seed is derived from the series' base seed, and separate streams for client
phases and for each flow's gaps are derived from it (splitmix64). Neighbouring repeats and flows
share no random sequence. The phases of node clocks come from the node's own generator, not from
the seed, as in a real deployment. Every report row records the configuration, the seeds, the code
revision and the host load before and after the run.

## Adversary models

The codes are used in every results table.

| Code | Adversary | What it sees and can do |
|---|---|---|
| A1 | Passive on both sides | timestamps and packet sizes on the client-to-entry and exit-to-recipient links |
| A2 | Passive on one side | the same, but only at the entry |
| A3 | Active network | delays, duplicates and drops cells, embeds a timing watermark in a flow |
| A4 | Node compromise | full access to one or two nodes of three, including process memory |
| A5 | Local on a machine | memory and disk of a node or a client during a session and after |
| A6 | Local with history | several snapshots of the container file over time |

The adversary knows the design and the source code. Security rests on keys and statistical
indistinguishability, not on the secrecy of the implementation.

## Metrics

### Linking sender and recipient

| Metric | Definition | Why it is used |
|---|---|---|
| ROC AUC | area under the error curve of the linking attack; a tie between a true and a false pair counts as half a pair | one number, comparable across configurations |
| Top-1 accuracy | share of entry flows whose highest-scoring exit flow is their own; when k exit flows tie for the highest score and the own one is among them, the flow counts 1/k | what an adversary that picks the best pair gets |
| TPR at FPR 0.01 | fraction of correctly linked pairs at a fixed false positive rate | an attack matters in the low false positive region |
| Precision at the base rate | fraction correct among positive decisions at the real number of flows | guards against a false claim: with a thousand flows AUC 0.9 is nearly useless to the adversary |
| Degree of anonymity | entropy of the posterior sender distribution over its maximum | a standard measure, comparable with the literature |
| Anonymity set size | number of candidates the adversary cannot separate | the intuitive form for the defence |

### Traffic indistinguishability

| Metric | Definition |
|---|---|
| Distinguisher AUC | a classifier separates payload cells from cover cells; 0.5 expected |
| Kolmogorov-Smirnov distance | between inter-arrival distributions of real and cover flows |
| Total variation estimate | an upper bound on the distinguishability of the two distributions |

### The price of protection

| Metric | Definition |
|---|---|
| Bandwidth multiplier | frames on a link within the observation window over messages handed to the clients. Reported separately for the client-entry link and for the observed link between nodes, in each direction. The window opens when the flows start sending: circuit setup and anything sent before it are excluded. A frame on the window boundary is excluded |
| Goodput | payload bytes per second per client |
| Latency | median, 95th and 99th percentile. The testbed measures the round trip: from handing a message to the client to the exit's echo coming back, matched to its message by sequence number, not by order |
| Cost per cell | nanoseconds of CPU and allocations to strip a layer |
| Cost per session | nanoseconds to agree a key, per suite |

### Key material hygiene

| Metric | Definition |
|---|---|
| Extraction success rate | in what fraction of N attempts the key is found in a dump |
| Key lifetime window | time from the end of a session until the key no longer appears in memory |
| Decrypted fraction after a node key theft | forward secrecy check: zero for a wire capture (links run on ephemeral keys); for a neighbour that kept the setup cells, the fraction of them whose layer opens with the keys in node memory, by the age of the cell at the moment of the theft. With onion key rotation it is expected to be one while the key of the cell is held and zero past the rotation period plus the descriptor lifetime plus the clock allowance; without rotation one for the whole time the node ran |

### Client container

| Metric | Definition |
|---|---|
| NIST STS pass rate | out of the 15 tests, over at least 100 containers |
| Entropy per byte | estimated from the sample, close to eight expected |
| Volume distinguisher AUC | a classifier separates one-volume from two-volume containers; 0.5 expected |
| Brute force cost | Argon2id parameters, time to open, cost estimate for a password of a given entropy |

## Experiment blocks

### Block 1. Flow linking, adversary A1

Baseline attack: correlation of cell counts in windows at the entry and the exit. Stronger attack:
gradient boosting over window features (cell count, variance of intervals, gap lengths,
autocorrelation). The adversary trains on one sample and is evaluated on another, split by time.

| Factor | Levels |
|---|---|
| Cover traffic | none, 0.5 of payload, 1.0, 2.0 |
| Cell size | constant, variable with message length |
| Node delay | none, sending on the node's own clock, uniform, exponential, batching by k cells |
| Concurrent flows | 2, 5, 10, 20 |
| Primitive suite | GOST, X25519 |

Plan: one factor at a time against the baseline, then a full factorial over the subset where cover
traffic and delay are expected to interact. The headline result is the curve of bandwidth
multiplier against attack AUC with confidence intervals.

### Block 2. Active adversary A3, timing watermark

The adversary delays cells at the entry following a pattern and looks for that pattern at the exit.
This is stronger than passive correlation and tests whether batching helps.

| Measured | Metric |
|---|---|
| Watermark detectability | AUC of the watermark detector at the exit |
| Resistance threshold | batching parameters at which the watermark stops being detected |
| Price of resistance | added delivery latency that buys it |
| Circuit survival | share of circuits still open at the end of a run and time to the first closed circuit, against the ratio of the node period to the client's, from the flow_closed and flow_closed_after fields of the report rows; one lost or reordered cell closes a circuit |

### Block 3. Node compromise, adversary A4

| Scenario | Metric |
|---|---|
| One node of three | what the node holds: neighbours, content, fraction of the route recovered |
| Entry and exit nodes | fraction of correctly linked pairs, time to link |
| Middle and one edge node | the same, for comparison |
| Inserted node with a valid certificate | fraction of intercepted sessions, fraction decrypted |
| Replay and tampering | share of replayed, reordered or altered cells that go no further than the first node that sees them (a cell out of turn closes the circuit, an altered one is dropped), one hundred percent expected |

The block concludes which share of the chain must be compromised to destroy the property, and
whether that matches the theoretical probability of picking a compromised chain.

### Block 4. Key material, adversary A5

| Scenario | Metric |
|---|---|
| Memory dump during a session | extraction success rate, build without measures against build with mlock and dumps disabled |
| Dump after the session | key lifetime window in seconds |
| Search on disk and in the image | found or not |
| Node key theft at a given age of the recorded setup cells | fraction of recorded setups whose layer opens, against the time from the recording to the theft, with and without onion key rotation |
| Client | whether the volume key is still in memory after the container is closed |

### Block 5. Client container, adversaries A5 and A6

| Scenario | Metric |
|---|---|
| Ciphertext statistics | NIST STS, entropy, chi-square |
| One volume against two | classifier AUC over a sample of containers |
| Several snapshots over time | fraction of cases where the changes reveal the hidden volume |
| Integrity | fraction of modifications detected, one hundred percent expected |
| Cost to open | time at the chosen Argon2id parameters on the target hardware |

For A6 the expected result is negative: against an adversary with snapshots the property does not
hold. It is reported as a measured boundary, not passed over.

### Block 6. Performance and primitive cost

| Measured | How |
|---|---|
| Key agreement | go test -bench, nanoseconds per operation, GOST against X25519 |
| Setup during the grace period | nanoseconds per setup at a node holding one and two onion keys, GOST against X25519: the second key costs a second agreement |
| Layer stripping | nanoseconds and allocations per cell |
| Node throughput | cells per second at saturation, on 1, 2 and 4 cores |
| Latency by hop count | one, two, three nodes; p50, p95, p99 |
| Cost of mlock | the same metrics with memory locking on and off |

## Statistics

- At least 30 clean repetitions per point (runs with no closed circuit and no node limit acting,
  clean_runs in the report), warm-up discarded.
- Series run on an idle host: concurrent load disturbs timing and lowers the AUC of individual
  runs. Tables report the median.
- Median and a 95 percent confidence interval, BCa bootstrap, 10000 resamples.
- Comparisons: Mann-Whitney U at 0.05, always with an effect size (Cliff's delta). A significant
  but negligible difference is reported as such.
- Multiple comparisons are corrected with Holm's method.
- Before a series, the sample size needed to detect an AUC difference of 0.05 at power 0.8 is
  computed.
- Adversary classifiers are trained and evaluated on separate samples, split by time, with no
  feature leakage.
- A relay closes a circuit when a counter breaks the order (a copy, a gap, a step back, a jump, or
  at the exit a first forward counter other than the one in its setup layer), a cell finds no room
  in a queue in either direction, a backward cell of another kind or one it cannot wrap arrives,
  the exit cannot seal a reply for any reason other than its length (a reply too long for a cell
  goes back as cover under the same number), or a cell cannot be written to the next node or back
  towards the client. A write on a link the node closed itself while closing a circuit is not
  counted again. A client closes its
  circuit on a reply out of turn, a reply that does not open, or a reply beyond the number of cells
  it wrote. The flow then stops before the run ends and its traces are shorter.
- A report row carries relay_broken_circuits (the sum of the closures each relay noticed, so one
  circuit can be counted by several relays), broken_flows (clients that closed their circuit) and,
  per flow, flow_closed and flow_closed_after: whether the circuit closed before the run was read,
  as the client saw it and whatever the cause, and how long after the flows started ("" for one
  that stayed open).
- A row also carries relay_timed_out (handshake, setup and write deadlines that ran out),
  relay_expired (circuits closed for idleness or age) and relay_refused (connections and setups
  the relays turned away), summed over the relays. A run is limited when any of them is non-zero:
  what it lost, it lost to a node limit and not to the configuration under test. A write deadline
  that ran out closes its circuit, so it shows in relay_timed_out and in relay_broken_circuits.
- A run is broken when any of the closure fields is non-zero. In the summary, runs counts every
  run, broken_runs the broken ones, limited_runs the limited ones (a run can be both) and
  clean_runs those that are neither; medians, ranges and ci_degenerate_runs rest on the clean
  runs. With none left those fields are null, and the latency median is null as well when the
  clean runs have no latency sample. A line resting on a single clean run gives that run's
  values, not a median, and the printed summary marks it.
- relay_dropped_cells counts cells the relays dropped: cells whose layer did not open, cells with
  an unparseable header, cells for an unknown circuit, control cells of a failed or refused setup
  (a layer that does not open, a copy of a setup seen before, a full tag cache, an identifier in
  use, a link that already carries a circuit, an unreachable next node), replies too long for a
  cell (a cover reply goes back under the same number), replies the exit could not write back, and
  cells still waiting in the queue of a circuit that closed.

## Threats to validity

| Type | Threat | What is done |
|---|---|---|
| Internal | the adversary sees ideal timestamps, unlike a real network | a separate series with network noise and jitter |
| Internal | synthetic load is too regular | a heavy-tailed traffic model and several activity profiles |
| External | the testbed runs on one machine, delays are modelled | results are reported as a function of the configured delay, not as absolute numbers |
| Construct | AUC alone does not imply a practical attack | precision at the real base rate is reported alongside |
| Reproducibility | randomness across runs | fixed seeds, configuration and code version in every report |
| Survival bias | medians without broken and limited runs describe the runs where every circuit survived; when closures depend on the configuration, such as a node period close to the client's, its medians describe the luckier runs | runs, broken_runs, limited_runs and clean_runs stand next to every median, and circuit survival is measured on its own |

## Comparison with existing systems

A table over the same features: Tor, Session, SimpleX, Briar and this work. Features: constant cell
size, cover traffic, state kept on a node, deniability, primitive suite, published latency figures.
Numbers for other systems come from their documentation and papers, ours are measured. No direct
performance comparison is made: the conditions differ, and that is stated.

## What the defence shows

1. A live message through three nodes and the panel of what each node learns.
2. The observer: without cover traffic the attack AUC is close to one, with cover traffic it falls
   towards 0.5. The system is broken and repaired in front of the committee.
3. The bandwidth multiplier against AUC curve with confidence intervals.
4. The key is found in a dump without the measures and is not found with mlock and dumps disabled.
5. The container: one password opens the decoy, another the real history, with NIST STS results
   next to it.
6. The cost table: GOST against X25519, latency by hop count.
