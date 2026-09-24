# Research programme

English | [Русский](../ru/EXPERIMENT.md)

The work answers one question: **what does resistance to traffic analysis cost in bandwidth and
latency in a three-hop chain with constant-size cells, and where does that resistance stop
working**. Everything else serves that answer.

Every run is reproducible: the configuration, the generator seed, the code version and the time
go into the report. Results live in artifacts/ and the figures are produced from those files.

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
| ROC AUC | area under the error curve of the linking attack | one number, comparable across configurations |
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
| Bandwidth multiplier | cells sent over cells carrying payload |
| Goodput | payload bytes per second per client |
| Latency | median, 95th and 99th percentile of delivery |
| Cost per cell | nanoseconds of CPU and allocations to strip a layer |
| Cost per session | nanoseconds to agree a key, per suite |

### Key material hygiene

| Metric | Definition |
|---|---|
| Extraction success rate | in what fraction of N attempts the key is found in a dump |
| Key lifetime window | time from the end of a session until the key no longer appears in memory |
| Decrypted fraction after a long-term key theft | forward secrecy check, zero expected |

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
| Node delay | none, uniform, exponential, batching by k cells |
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
| Loss tolerance | fraction of dropped cells at which the circuit breaks |

### Block 3. Node compromise, adversary A4

| Scenario | Metric |
|---|---|
| One node of three | what the node holds: neighbours, content, fraction of the route recovered |
| Entry and exit nodes | fraction of correctly linked pairs, time to link |
| Middle and one edge node | the same, for comparison |
| Inserted node with a valid certificate | fraction of intercepted sessions, fraction decrypted |
| Replay and tampering | fraction rejected, one hundred percent expected |

The block concludes which share of the chain must be compromised to destroy the property, and
whether that matches the theoretical probability of picking a compromised chain.

### Block 4. Key material, adversary A5

| Scenario | Metric |
|---|---|
| Memory dump during a session | extraction success rate, build without measures against build with mlock and dumps disabled |
| Dump after the session | key lifetime window in seconds |
| Search on disk and in the image | found or not |
| Long-term node key theft | fraction decrypted from recorded traffic |
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
| Layer stripping | nanoseconds and allocations per cell |
| Node throughput | cells per second at saturation, on 1, 2 and 4 cores |
| Latency by hop count | one, two, three nodes; p50, p95, p99 |
| Cost of mlock | the same metrics with memory locking on and off |

## Statistics

- At least 30 repetitions per point, warm-up discarded.
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

## Threats to validity

| Type | Threat | What is done |
|---|---|---|
| Internal | the adversary sees ideal timestamps, unlike a real network | a separate series with network noise and jitter |
| Internal | synthetic load is too regular | a heavy-tailed traffic model and several activity profiles |
| External | the testbed runs on one machine, delays are modelled | results are reported as a function of the configured delay, not as absolute numbers |
| Construct | AUC alone does not imply a practical attack | precision at the real base rate is reported alongside |
| Reproducibility | randomness across runs | fixed seeds, configuration and code version in every report |

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
