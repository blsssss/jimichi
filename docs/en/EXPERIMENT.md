# Research programme

English | [Русский](../ru/EXPERIMENT.md)

The work answers one question: **what does resistance to traffic analysis cost in bandwidth and
latency in a three-hop chain with constant-size cells, and where does that resistance stop
working**. Everything else serves that answer.

Every run is reproducible: the configuration, the generator seed, the code version and the time
go into the report. Results live in artifacts/ and the figures are produced from those files.

Real clients start at unrelated moments, so in the lab harness each client's schedule gets a random
phase drawn from the run's seed. Clients started back to back would tick almost in phase and hand
the attack ties that a real network does not produce. The observation window also opens at a
random moment relative to the schedules; otherwise the last client to start would tick in step with
the windows.

Seeds: each repeat's seed is derived from the series' base seed, and separate streams for client
phases and for each flow's gaps are derived from it (splitmix64). Neighbouring repeats and flows
share no random sequence. The chains sampled in block 3 are drawn from a stream of their own,
derived from the seed in the same way. The phases of node clocks come from the node's own
generator, not from the seed, as in a real deployment. Every report row records the
configuration, the seeds, the code revision and the host load before and after the run.

## Adversary models

The codes are used in every results table. Measured so far: A1 with the count correlation attack
(block 1) and the choice of chains for A4 (block 3). The experiments for A3, A5 and A6 are
planned, see the status of each block; A2 has no block of its own yet.

| Code | Adversary | What it sees and can do |
|---|---|---|
| A1 | Passive on both sides | timestamps and packet sizes on the client-to-entry and exit-to-recipient links. There is no recipient yet ([#18](https://github.com/jimichi-org/jimichi/issues/18), [#47](https://github.com/jimichi-org/jimichi/issues/47)): the lab observer takes the link into the last node as the far side, and the last node echoes the message back |
| A2 | Passive on one side | the same, but only at the entry |
| A3 | Active network | delays, duplicates and drops cells, embeds a timing watermark in a flow |
| A4 | Node compromise | full access to some of the nodes, including process memory: one or two of the three nodes of a chain, k of the N nodes a client draws its chains from |
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
| Precision at the base rate (planned) | fraction correct among positive decisions at the real number of flows | guards against a false claim: with a thousand flows AUC 0.9 is nearly useless to the adversary |
| Degree of anonymity (planned) | entropy of the posterior sender distribution over its maximum | a standard measure, comparable with the literature |
| Anonymity set size (planned) | number of candidates the adversary cannot separate | the intuitive form for the defence |

The lab computes ROC AUC, top-1 accuracy and TPR at FPR 0.01. The three metrics marked as planned
are not computed yet ([#119](https://github.com/jimichi-org/jimichi/issues/119)).

### Compromised chains

| Metric | Definition |
|---|---|
| Share of chains with a rogue entry and exit | share of the chains whose first and last node are both rogue, that is held by the adversary, who then links the two ends of the circuit; a chain of one node counts when that node is rogue. A uniform choice of h distinct nodes among N, k of them rogue, gives k(k-1)/(N(N-1)), and k/N for h = 1 |
| Share of chains with a rogue node | share of the chains that hold at least one rogue node; a uniform choice gives 1 - C(N-k,h)/C(N,h) |
| Share of refused attempts | share of the attempts to build a chain whose entry serves a mirror the client refuses, one that lacks more than min(-missing, N - h) listed nodes |
| Share of attempts failed at setup | share of the attempts in which the client chooses a chain the nodes do not set up: an honest node extends a circuit only to a node whose verified descriptor it holds, so a chain with an honest node directly before a node that withholds its descriptor fails. The two shares of chains above are taken over the chains that come up |
| Standard error of a share | sqrt(p(1-p)/n) for a share of n independent draws at the value p the model gives; n is the number of chains that came up, and the number of attempts for the refused and the failed shares |

### Traffic indistinguishability

Status: planned, not implemented ([#119](https://github.com/jimichi-org/jimichi/issues/119)). The
lab has no distinguisher of payload and cover cells and does not compare inter-arrival
distributions yet.

| Metric | Definition |
|---|---|
| Distinguisher AUC | a classifier separates payload cells from cover cells; 0.5 expected |
| Kolmogorov-Smirnov distance | between inter-arrival distributions of real and cover flows |
| Total variation estimate | an upper bound on the distinguishability of the two distributions |

### The price of protection

| Metric | Definition |
|---|---|
| Bandwidth multiplier | frames on a link within the observation window over messages handed to the clients. Reported separately for the client-entry link and for the observed link between nodes, in each direction. The window opens when the flows start sending: circuit setup and anything sent before it are excluded. A frame on the window boundary is excluded |
| Goodput (planned, [#118](https://github.com/jimichi-org/jimichi/issues/118)) | payload bytes per second per client |
| Latency | median, 95th and 99th percentile. The lab harness measures the round trip: from handing a message to the client to the exit's echo coming back, matched to its message by sequence number, not by order |
| Cost per cell | nanoseconds of CPU and allocations to strip a layer |
| Cost per session | nanoseconds to agree a key, per suite |

### Key material hygiene

Status: planned, not implemented ([#24](https://github.com/jimichi-org/jimichi/issues/24)). The
lab takes no memory dumps and records no setup cells yet. That a replaced onion key stops opening
setups after its release is covered by the tests of the node; the fraction against the age of a
cell is not measured.

| Metric | Definition |
|---|---|
| Extraction success rate | in what fraction of N attempts the key is found in a dump |
| Key lifetime window | time from the end of a session until the key no longer appears in memory |
| Decrypted fraction after a node key theft | forward secrecy check: zero for a wire capture (links run on ephemeral keys); for a neighbour that kept the setup cells, the fraction of them whose layer opens with the keys in node memory, by the age of the cell at the moment of the theft. With onion key rotation it is expected to be one while the key of the cell is held and zero past the rotation period plus the descriptor lifetime plus the clock allowance; without rotation one for the whole time the node ran |

### Client container

Status: planned, not implemented ([#20](https://github.com/jimichi-org/jimichi/issues/20)). NIST
STS and entropy can show only that the ciphertext has no statistical structure; they do not show
that a second volume is deniable. That is the task of the volume distinguisher.

| Metric | Definition |
|---|---|
| NIST STS pass rate | out of the 15 tests, over at least 100 containers |
| Entropy per byte | estimated from the sample, close to eight expected |
| Volume distinguisher AUC | a classifier separates one-volume from two-volume containers; 0.5 expected |
| Brute force cost | Argon2id parameters, time to open, cost estimate for a password of a given entropy |

## Experiment blocks

### Block 1. Flow linking, adversary A1

Status: partly implemented. The lab runs the baseline attack over the series with cover traffic,
a constant rate at the client and nodes on their own clocks; the rest of this block is planned.

Baseline attack, implemented: Pearson correlation of cell counts per window on the client-entry
link and on the link into the last node, every entry flow against every exit flow. Stronger
attack, planned: gradient boosting over window features (cell count, variance of intervals, gap
lengths, autocorrelation), trained on one sample and evaluated on another, split by time. A
deep-learning correlator as the strongest adversary is planned as well
([#67](https://github.com/jimichi-org/jimichi/issues/67)).

| Factor | Levels |
|---|---|
| Cover traffic | none, 0.5 of payload, 1.0, 2.0 |
| Client schedule | at once, constant rate where a payload takes the slot of a cover cell |
| Cell size | constant; a variable size is not implemented: the cell has one size and no switch, so this factor is not measured. Message size classes are planned ([#68](https://github.com/jimichi-org/jimichi/issues/68)) |
| Node delay | none, sending on the node's own clock; uniform, exponential and batching by k cells are planned ([#45](https://github.com/jimichi-org/jimichi/issues/45), [#82](https://github.com/jimichi-org/jimichi/issues/82)) |
| Concurrent flows | 2, 5, 10, 20 |
| Primitive suite | GOST, X25519 |

Plan: one factor at a time against the baseline, then a full factorial over the subset where cover
traffic and delay are expected to interact. The headline result is the curve of bandwidth
multiplier against attack AUC; confidence intervals across runs are planned with the full series
([#23](https://github.com/jimichi-org/jimichi/issues/23)).

### Block 2. Active adversary A3, timing watermark

Status: planned, not implemented ([#116](https://github.com/jimichi-org/jimichi/issues/116)). The
lab has no active adversary and no watermark detector, and batching at nodes, which this block
will test, is planned as well ([#82](https://github.com/jimichi-org/jimichi/issues/82)). Of the
table below only the flow_closed and flow_closed_after fields of the report rows exist; the lab
has no series over the ratio of periods.

The adversary will delay cells at the entry following a pattern and look for that pattern at the
exit. This is stronger than passive correlation and will test whether batching helps.

| Measured | Metric |
|---|---|
| Watermark detectability | AUC of the watermark detector at the exit |
| Resistance threshold | batching parameters at which the watermark stops being detected |
| Price of resistance | added delivery latency that buys it |
| Circuit survival | share of circuits still open at the end of a run and time to the first closed circuit, against the ratio of the node period to the client's, from the flow_closed and flow_closed_after fields of the report rows; one lost or reordered cell closes a circuit |

### Block 3. Node compromise, adversary A4

Status: partly implemented. The choice of the chain is measured (`cmd/lab -set paths`). The other
scenarios are planned ([#117](https://github.com/jimichi-org/jimichi/issues/117)): the lab has no
scenario with a compromised or inserted node, and replay and tampering are covered by the tests
of the node and of the client, not measured as a share.

| Scenario | Metric |
|---|---|
| One node of three | what the node holds: neighbours, content, fraction of the route recovered |
| Entry and exit nodes | fraction of correctly linked pairs, time to link |
| Middle and one edge node | the same, for comparison |
| Inserted node with a valid certificate | fraction of intercepted sessions, fraction decrypted |
| Choice of the chain with k rogue nodes among N | share of chains with a rogue entry and exit and share of chains with a rogue node, over the chains that come up among those drawn with the client's own choice, against the values the model gives: with full mirrors, with rogue entries that leave honest nodes out of their mirrors, and with rogue nodes that withhold their descriptors |
| Ordered pairs of nodes kept busy from one address (planned, [#125](https://github.com/jimichi-org/jimichi/issues/125)) | share of the surviving chains with a rogue entry and exit and with a rogue node, against the addresses and circuits the adversary spends (LIMITATIONS, node limits) |
| Replay and tampering | share of replayed, reordered or altered cells that go no further than the first party able to check them: forward that is the first node that sees them (a cell out of turn closes the circuit, an altered one is dropped); backward the first node checks the order, and the altered body of a reply is checked only by the client, which closes the circuit; one hundred percent expected |

The block is to conclude which share of the chain must be compromised to destroy the property,
and whether that matches the theoretical probability of picking a compromised chain.

The choice of the chain is measured without traffic and without nodes. `cmd/lab -set paths` makes
-samples attempts to draw a chain of -hops nodes among -nodes the way the client does, with the
client's own functions for the entry, for taking or refusing its mirror and for the rest of the
chain, on a stream derived from -seed in place of the system generator: the entry among all the
nodes, a refusal when its mirror lacks more than min(-missing, N - h) of them (the bound), the
other hops among the nodes the mirror holds. A chosen chain then comes up when every node on it
extends the circuit to the next one, and here the lab applies the rule of the node: an honest
node extends only to a node whose descriptor it holds, a rogue node to any node. The first
-rogue nodes are rogue and act together:

| Flag | What the rogue nodes do | What it does to the chains |
|---|---|---|
| -leftout o | as an entry each leaves o honest nodes out of its mirror | the exit of a rogue entry is drawn among N - o - 1 nodes, k - 1 of them rogue |
| -withhold w | w of them keep their descriptors from the honest nodes | the mirror of an honest entry lacks w nodes: within the bound its chain is drawn among the N - w nodes the mirror holds, beyond it the attempt is refused. No honest node extends a circuit to a withholding node, so a chain chosen through a rogue entry fails at setup when an honest node stands directly before one |

With both at 0, the default, every mirror is full, every chain comes up and the choice is the
uniform one. An attempt ends in one of three ways: it is refused, its chain fails at setup, or
its chain comes up. The report gives the shares of refused and of failed attempts and, over the
chains that came up, the two shares of chains, each next to the value the model gives and the
standard error of a share at that value, and the values of a uniform choice next to them. A
configuration in which no attempt gives a chain that comes up is turned away: there is no chain
to take a share of. The report row carries nodes, hops, rogue_nodes, missing, left_out,
withheld, samples, seed and rev, so the same sample can be drawn again. The report file is named
after all of these but rev and after the second it is written in, so two runs within one second
overwrite each other only when they differ in nothing but rev.

Rows drawn at one seed read the same stream: while no attempt is refused they draw the same
entries, and an honest entry with a full mirror draws the same chain. Such rows are not
independent samples, and their shares can coincide to the last digit: with -leftout within the
bound and no -withhold the sampled share of chains with a rogue node is that of full mirrors at
the same seed. Rows meant as independent samples take different seeds.

The values the model gives are computed exactly, the chains of a rogue entry by summing over
the kind of node in each position, and are checked in the tests of the metric against every
chain the client can choose, taken one by one. A sampled share differs from its value by about
the standard error. Where the value is 0 or 1 the share is exact by construction: every draw
gives the same answer, the sampled share equals the value for any seed and any number of
samples, the standard error is 0, and the row says nothing about the choice. The common cases:

| Row | Exact share |
|---|---|
| no rogue node, or every node rogue | both shares of chains, 0 or 1 |
| one rogue node, chains of two nodes or more | a rogue entry and exit, 0 |
| two rogue nodes, both withholding, chains of three nodes or more | a rogue entry and exit, 0: an honest node stands before the exit and does not extend to it |
| fewer honest nodes than hops | a rogue node, 1 |
| the mirrors of the honest entries are refused (-withhold above the bound) | a rogue node, 1 |
| the mirrors of the rogue entries are refused (-leftout above the bound) | a rogue entry and exit, 0 |
| no mirror lacks more than the bound | refused attempts, 0 |
| no node withholds, or chains of one or two nodes | attempts failed at setup, 0 |

For N = 5, k = 2 and h = 3 there are 5 * 4 * 3 = 60 ordered chains. Six have rogue nodes at both
ends (2 choices of the entry, the other rogue node as the exit, any of the 3 honest nodes
between them): 6/60 = 0.1 = k(k-1)/(N(N-1)). Six hold no rogue node (the three honest nodes in
any order), so 54/60 = 0.9 = 1 - C(3,3)/C(5,3) hold one. The test of the metric enumerates the
60 chains and requires exactly these values.

With -leftout 1 in the same configuration a rogue entry serves four nodes and draws its two
further hops among the three others: 3 * 2 = 6 chains, two of them ending at the other rogue
node. An honest entry serves all five: 4 * 3 = 12 chains, ten of them with a rogue node. The
entry is any node with 1/5, so both ends are rogue with 2/5 * 2/6 = 2/15 against 0.1 for full
mirrors, and a rogue node is in 2/5 + 3/5 * 10/12 = 0.9 of the chains, as before. No node
withholds its descriptor here, so every chain comes up.

With -withhold 2 and -missing 1 the mirrors of the three honest nodes lack two nodes and are
refused, 3/5 of the attempts. Every chain the client chooses enters through a rogue node, which
serves all five: 12 chains. In three of them an honest node stands before the other rogue node,
whose descriptor it does not hold, and the chain fails at setup: 2/5 * 3/12 = 1/10 of the
attempts. The other nine come up, 3/10 of the attempts, and each ends at an honest node. So of
the chains that come up every one holds a rogue node and none has a rogue entry and exit, where
the choice alone, before setup, gives 3/12 = 1/4: by withholding, the two nodes take every entry
and lose the exit. With -withhold 1 nothing is refused, 1/20 of the attempts fail at setup, and
of the chains that come up 1/19 have a rogue entry and exit and 15/19 a rogue node. The tests
enumerate the chains of these cases as well.

The correlation series of block 1 run with as many nodes as hops, in an order the harness sets
itself: the choice of the chain does not enter them. The harness starts the nodes and the clients
inside one process and connects them over loopback, not in the cluster, so there is no network
delay between them. Its nodes run without certificates, with anonymous links between nodes,
without onion key rotation and with the per-address limits off, and the last node echoes every
message.

### Block 4. Key material, adversary A5

Status: planned, not implemented ([#24](https://github.com/jimichi-org/jimichi/issues/24)). The
measures are switched by the -keymem and -harden flags of the node and the client; the scenarios
with memory dumps, the search on disk and the recording of setup cells do not exist yet. The
client row waits for the container ([#20](https://github.com/jimichi-org/jimichi/issues/20)).

| Scenario | Metric |
|---|---|
| Memory dump of a node during a session | extraction success rate, a run without the measures (-keymem none, -harden=false) against a run with mlock and dumps disabled |
| Dump after the session | key lifetime window in seconds |
| Search on disk and in the image | found or not |
| Node key theft at a given age of the recorded setup cells | fraction of recorded setups whose layer opens, against the time from the recording to the theft, with and without onion key rotation |
| Client | whether the volume key is still in memory after the container is closed |

### Block 5. Client container, adversaries A5 and A6

Status: planned, not implemented ([#20](https://github.com/jimichi-org/jimichi/issues/20)).

| Scenario | Metric |
|---|---|
| Ciphertext statistics | NIST STS, entropy, chi-square |
| One volume against two | classifier AUC over a sample of containers |
| Several snapshots over time | fraction of cases where the changes reveal the hidden volume |
| Integrity | fraction of modifications detected, one hundred percent expected |
| Cost to open | time at the chosen Argon2id parameters on the target hardware |

For A6 the expected result is negative: against an adversary with snapshots the property does not
hold. It will be reported as a measured boundary, not passed over.

### Block 6. Performance and primitive cost

Status: partly implemented. go test -bench covers key generation, key agreement, signing,
verification and one AEAD layer of a cell on both suites (crypto/suite) and sealing a cell and
layer stripping on c25519 (wire). The lab reports round-trip latency for chains of two and more
nodes. Planned ([#118](https://github.com/jimichi-org/jimichi/issues/118)): the setup benchmark
at a node with one and two onion keys, node throughput at saturation, goodput per client, latency
for a chain of one node (the lab takes no fewer than two hops) and the cost of memory locking (the
lab and the benchmarks have no switch for the key-memory measures).

| Measured | How |
|---|---|
| Key agreement | go test -bench, nanoseconds per operation, GOST against X25519 |
| Setup during the grace period | nanoseconds per setup at a node holding one and two onion keys, GOST against X25519: the second key costs a second agreement, paid only during the grace period, 22 minutes of every hour on the testbed |
| Layer stripping | nanoseconds and allocations per cell |
| Node throughput | cells per second at saturation, on 1, 2 and 4 cores |
| Latency by hop count | one, two, three nodes; p50, p95, p99 |
| Cost of mlock | the same metrics with memory locking on and off |

The binding of every derived key to the transcript, the suite and the scheme version has no
switch, like the setup replay tag and the link confirmation frame: a build without it would be a
second key schedule, that is, a downgrade path. No block measures its contribution. The
benchmarks of crypto/suite time its parts apart: the transcript hash (BenchmarkNewContext, once
per hop on each side and once per link handshake), the agreement under a context
(BenchmarkAgree), the keys of one hop (BenchmarkDeriveHopKeys) and the chaining of two agreements
on an authenticated link (BenchmarkMixKey). Release v0.2.0, the last one without the binding,
has only the agreement benchmark to compare with.

## Statistics

- Target for the full series ([#23](https://github.com/jimichi-org/jimichi/issues/23)): at least 30
  clean repetitions per point (runs with no closed circuit and no node limit acting, clean_runs
  in the report). The series published so far is preliminary and has fewer runs per point. The
  observation window opens when the flows start sending, so circuit setup falls outside it; no
  further warm-up is discarded.
- Series run on an idle host: concurrent load disturbs timing and lowers the AUC of individual
  runs. Tables report the median.
- Within a run the AUC carries a 95 percent confidence interval: BCa bootstrap over flows, 10000
  resamples. Across repeats the summary gives the median, the minimum and the maximum; an
  interval for the median across repeats is planned with the full series
  ([#23](https://github.com/jimichi-org/jimichi/issues/23)).
- Planned with the full series ([#23](https://github.com/jimichi-org/jimichi/issues/23)):
  comparisons by Mann-Whitney U at 0.05, always with an effect size (Cliff's delta), a
  significant but negligible difference reported as such; Holm's correction for multiple
  comparisons; the sample size needed to detect an AUC difference of 0.05 at power 0.8, computed
  before a series.
- The attack implemented so far has no training step. A learned attack, once added, will be
  trained and evaluated on separate samples, split by time, with no feature leakage.
- A relay closes a circuit when a counter breaks the order (a copy, a gap, a step back, a jump, or
  at the exit a first forward counter other than the one in its setup layer), a cell finds no room
  in a queue in either direction, a backward cell of another kind or one it cannot wrap arrives,
  the exit cannot seal a reply for any reason other than its length (a reply too long for a cell
  goes back as cover under the same number), or a cell cannot be written to the next node or back
  towards the client. A write on a link the node closed itself while closing a circuit is not
  counted again. A client closes its circuit on a reply with a bad header, a reply that does not
  open, a reply out of turn, or a reply beyond the number of cells it wrote. The flow then stops
  before the run ends and its traces are shorter.
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
  cell (a cover reply goes back under the same number), cells still waiting in the queue of a
  circuit that closed and, when a node forwards at once, cells towards the next node and replies
  of the exit whose write met a link that node had already closed itself. A write that fails for
  any other reason closes the circuit and is counted in relay_broken_circuits, not here.

## Threats to validity

| Type | Threat | What is done |
|---|---|---|
| Internal | the adversary sees ideal timestamps, unlike a real network | planned: a separate series with network noise and jitter ([#46](https://github.com/jimichi-org/jimichi/issues/46)); until then the lab observer has ideal timestamps |
| Internal | synthetic load is too regular | messages leave with exponential gaps, one profile; a heavy-tailed model and several activity profiles are planned |
| External | the testbed runs on one machine and the series in one process over loopback, network delays are not modelled | absolute latency figures belong to loopback and do not carry over to a network; network emulation profiles are planned ([#46](https://github.com/jimichi-org/jimichi/issues/46)) |
| Construct | AUC alone does not imply a practical attack | TPR at FPR 0.01 and top-1 accuracy are reported alongside; precision at the real base rate is planned ([#119](https://github.com/jimichi-org/jimichi/issues/119)) |
| Reproducibility | randomness across runs | fixed seeds, configuration and code version in every report |
| Survival bias | medians without broken and limited runs describe the runs where every circuit survived; when closures depend on the configuration, such as a node period close to the client's, its medians describe the luckier runs | runs, broken_runs, limited_runs and clean_runs stand next to every median, and every row records which circuits closed and when (flow_closed, flow_closed_after); a survival series over the ratio of periods is planned (block 2) |

## Comparison with existing systems

Planned: a table over the same features for Tor, Session, SimpleX, Briar and this work. Features:
constant cell size, cover traffic, state kept on a node, deniability, primitive suite, published
latency figures. Of the deniability properties this work has today only deniability of sending
at a constant rate and nothing to surrender after a session (THREAT_MODEL); deniable authentication
([#19](https://github.com/jimichi-org/jimichi/issues/19)) and the client container
([#20](https://github.com/jimichi-org/jimichi/issues/20)) are planned. Numbers for other systems
will come from their documentation and papers, ours will be measured. No direct performance
comparison will be made: the conditions differ, and that will be stated.

## What the defence shows

1. A live message through three nodes. The panel of what each node learns is planned with the
   dashboard ([#21](https://github.com/jimichi-org/jimichi/issues/21)).
2. The observer: the linking attack runs without protection and with each measure in turn. Cover
   traffic on top of the payload is not expected to lower its AUC: in the preliminary series only
   nodes sending on their own clocks brought it close to chance ([README](../../README.md)). A
   live view of the attack result is planned with the dashboard
   ([#21](https://github.com/jimichi-org/jimichi/issues/21)).
3. The bandwidth multiplier against AUC curve. The published figure has no intervals; confidence
   intervals across runs are planned with the full series
   ([#23](https://github.com/jimichi-org/jimichi/issues/23)).
4. Planned ([#24](https://github.com/jimichi-org/jimichi/issues/24)): the search for key bytes in
   memory dumps with and without the key-memory measures. The measured result will be shown as
   it is; copies of keys that libraries keep on the heap are listed in [CRYPTO](CRYPTO.md),
   "Known gaps".
5. Planned ([#20](https://github.com/jimichi-org/jimichi/issues/20)): the container, where one
   password opens the decoy and another the real history. NIST STS results next to it will show
   only that the ciphertext has no statistical structure; they say nothing about deniability.
6. The cost table: GOST against X25519 from the benchmarks and round-trip latency for chains of
   two and three nodes; the rest of block 6 is planned
   ([#118](https://github.com/jimichi-org/jimichi/issues/118)).
