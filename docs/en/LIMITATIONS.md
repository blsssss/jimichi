# Limits of applicability

English | [Русский](../ru/LIMITATIONS.md)

- The testbed is a laboratory one. In the cluster the nodes are containers on a single machine.
  The correlation series do not run in the cluster: cmd/lab starts every node and every client
  inside one process and connects them over loopback. Network delay, loss and jitter are neither
  reproduced nor emulated; network emulation is planned
  ([#46](https://github.com/jimichi-org/jimichi/issues/46)). The separation between operators is
  modelled only as the number of rogue nodes in the choice of a chain (EXPERIMENT, block 3).
- The GOST implementation is not a certified cryptographic facility. It applies to systems handling
  commercial data, not to state information systems or significant critical infrastructure. The
  algorithms are the same and conformance is checked against the test vectors from the standards,
  but no protection class is claimed.
- The two suites do not mix. A node runs one suite, and a client refuses an anchor or a
  descriptor of the other one, so GOST users and c25519 users form two separate networks and two
  separate anonymity sets. The suite is not hidden from an observer: the link handshake opens
  with 33 bytes from the initiator on c25519 and 65 on GOST, and descriptors travel over plain
  HTTP with the suite named in them. Frames after the handshake are 528 bytes on both. Hiding the
  suite and the role in the first flight of the handshake is planned
  ([#57](https://github.com/jimichi-org/jimichi/issues/57)).
- Go runtime: libraries keep their own copies of keys on the heap. The AEAD working key in
  x/crypto stays there for the life of the circuit or link and is never wiped: it remains after
  that until the memory is reused. secmem protects only its own buffers; CRYPTO lists the copies.
  Building the AEAD state per call from the secmem key is planned
  ([#39](https://github.com/jimichi-org/jimichi/issues/39)).
- mlock keeps only the secmem buffers out of swap. The heap copies listed above lie on ordinary
  pages and can be written to swap; locking all process memory is planned
  ([#36](https://github.com/jimichi-org/jimichi/issues/36)). mlock does not stop reading by a
  process with sufficient privileges either. Against root on the machine hosting a node,
  process-level measures do not work; that is the expected result.
- Sending on a node's own clock requires the node's period to be shorter than the client's, with a
  margin of a few percent. The node does not know how fast a client sends: if the client sends more
  often, the node's queue fills up and the circuit closes, since the node cannot lose a cell of a
  circuit. With equal or longer periods a missed tick can never be caught up, and the queue fills
  up sooner or later. The testbed gives nodes a period 5% shorter than the client's.
- Delivery is not guaranteed. At a constant rate the client queues at most 256 messages and drops
  a new one without an error when the queue is full, counting it only; a message in the queue or
  on the way is lost when its circuit closes. Nothing acknowledges or resends a message, and a
  reply is dropped when the application has 64 of them unread.
- Any break in the counter order closes the circuit. A neighbouring node can cause one with a
  single cell. A party on the wire cannot put a frame of its own on an authenticated link, but a
  frame it damages or a connection it breaks closes the circuit all the same. This is a denial of
  service.
- A link is authenticated in one direction, to the node it leads to. The responder does not
  authenticate the initiator: a node cannot tell a roster node from a client or from anyone else
  who connects to its cell port.
- The baseline without node authentication (-auth=false) extends a circuit to any address named
  in the setup cell, and its links between nodes are anonymous: they hide headers from a passive
  observer only. Its client takes the unverified keys of every hop from the entry alone, and a
  node serves them only when started with -advertise and -peers. No experiment block compares it
  with the authenticated configuration. The lab harness works without certificates as well: its
  nodes have no roster, the links between them are anonymous, and its clients get the node keys
  from the harness.
- The entry serves the bundles of the listed nodes it holds. It cannot alter them, but it can
  withhold the mirror: the client then exits and draws another entry at its next start. It can
  also leave out up to -missing listed nodes (one by default), and the chain is then drawn among
  the rest. On the testbed (five nodes, chains of three, two rogue nodes) both ends of a chain
  are rogue with probability 2/5 x 1/4 = 0.1 when no node is left out, and 2/5 x 1/3 = 2/15 when
  a rogue entry leaves out one honest node: the exit is then drawn among three nodes, one of them
  rogue. The entry also sees when a client prepares a circuit: the request for the descriptors
  precedes the setup.
- A node that withholds its descriptor from the others removes itself from their mirrors. When
  more nodes do so than -missing allows, the mirrors of honest nodes no longer satisfy a client
  and only the mirrors of the withholding nodes do, so -missing has to be at least the number of
  nodes assumed to misbehave, and a larger value gives a rogue entry more room to steer. There is
  no directory signed by several parties that would settle which nodes exist.
- A node can serve a different validly signed onion key to each of the other nodes. The key that
  opens a setup cell then tells it whose mirror the client used, so a rogue exit can learn the
  entry of a circuit and with it the whole chain of three.
- The node list of a client is static: there is no node discovery and no directory. The setup
  cell bounds a chain at four hops on c25519 and three on GOST. The roster a node accepts bounds
  the network: 4 KiB hold 58 nodes of the testbed address form on c25519 and 57 on GOST.
- A node that refuses or breaks the circuits it does not like decides which chains survive: the
  client exits on a failure, draws a new chain at its next start and keeps no account of
  failures, so rogue nodes can raise the share of surviving chains that run through them. This
  selective denial of service is neither prevented nor measured.
- There are no guard nodes: every circuit draws a fresh entry. One chain has a rogue entry and a
  rogue exit with probability p = k(k-1)/(N(N-1)), 0.1 for two rogue nodes of five (EXPERIMENT,
  block 3). Over c circuits with chains drawn independently the chance that at least one had
  both is 1 - (1 - p)^c, which grows towards one with every restart of the client.
- A node keeps a peer's descriptor until it expires. After a peer restarts, the mirror serves its
  previous bundle for up to the descriptor lifetime (20 min), and circuits through that peer fail
  at setup: the new process holds another link key and does not pass the link handshake. A
  rotation of the peer's onion key has no such effect: the peer holds the replaced key until
  that bundle has expired.
- Whoever installs a roster chooses which hosts a node polls on the info port: the node sends a
  GET for /descriptor to port -peer-info-port of every roster address when its entry is due,
  and goes on asking, with a 5 s pause between passes, for as long as the peer is missing or the
  entry stays due, which includes a peer that still serves the descriptor it has not signed
  again. A pass asks such peers in turn, each within the 5 s fetch timeout, so no roster address
  is asked more often than once in 5 s. The bound is per address and not per host: a host named
  by several roster addresses, which may differ in the port alone, or by several names that
  resolve to it gets one request per such address in a pass, and an address whose answer does
  not verify is asked in every pass. The addresses are IP literals and DNS names only, and an
  answer counts only if it verifies under the roster's anchor.
- A link is covered by own-clock sending only if the node sending on it has the measure turned on.
  The client cannot check that the nodes of its chain do: a node without the measure carries the
  timing onwards, and the protection is gone on its outgoing links.
- A node does not mix. It adds no random delay, gathers no batches and does not reorder cells
  between circuits: it forwards a cell at once or, with own-clock sending, sends one frame per
  tick in the order of arrival within the circuit. The wait for a tick, behind the cells that
  arrived earlier, is the only delay it adds. A node delay level is planned
  ([#45](https://github.com/jimichi-org/jimichi/issues/45)), mixing with reordering across
  circuits as well ([#82](https://github.com/jimichi-org/jimichi/issues/82)).
- Every circuit runs over a connection of its own, and a second setup on a link that already
  carries a circuit is dropped. Otherwise a second timer on the same link would double its frame
  rate and give away the number of circuits.
- There is no isolation per contact. A client holds one circuit, one send queue and one schedule,
  and everything it sends goes through them; the code has no notion of a contact. With several
  contacts all of them would share one chain and one exit. Circuits and queues per contact are
  planned ([#96](https://github.com/jimichi-org/jimichi/issues/96)).
- Without own-clock sending the exit's reply leaves after the message is delivered, and at once for
  a cover cell. The delivery time enters the moment of the reply; on the testbed delivery is an
  echo taking microseconds, a real recipient would make it noticeable.
- There is no recipient client and no end-to-end layer: the innermost layer ends at the exit,
  which reads the payload in clear and, on the testbed, echoes it back. Whoever runs the exit
  reads the messages, and nothing is delivered beyond it. A recipient and an end-to-end layer are
  planned ([#18](https://github.com/jimichi-org/jimichi/issues/18)), deniable authentication
  between clients after them ([#19](https://github.com/jimichi-org/jimichi/issues/19)).
- The circuit setup cell leaves at once, not on the node's clock. Together with the TCP connection
  opening it marks the start of the circuit on every link, which is the same signal as the moment
  the connection opens.
- Forward secrecy of the circuit layers reaches as far as the life of the onion key. With
  -onion-rotate a setup cell kept by a neighbour opens only while the node holds the key it was
  built for: at most the rotation period plus the descriptor lifetime plus the clock allowance
  (Skew, 2 min) after that key was first published. The rotation period is -onion-rotate, or the
  descriptor lifetime plus the allowance when that is longer, since a rotation waits for the
  release of the replaced key. On the testbed (-onion-rotate 1 h, -descriptor-ttl 20 min) that
  is 1 h + 20 min + 2 min = 1 h 22 min; with the defaults of the binary (1 h and 1 h) it is
  1 h 2 min + 1 h + 2 min = 2 h 4 min. Node memory taken after the release does not open the
  cell. A wire capture cannot be read without the links' ephemeral keys.
- The window is counted on two clocks, the wall clock and the running time of the host, and each
  of its two steps, the rotation and the release, happens as soon as either clock says so. The
  node reads them once a second, so each step can come up to a second late. A host that sleeps
  does not extend the window beyond its waking: the first reading after it goes by the wall
  clock. A wall clock set back does not extend it: the running time ends the period. A wall
  clock set forwards ends it early, and clients holding the replaced key are refused. The window
  is exceeded while the node cannot act: a sleeping host and a frozen process keep their memory
  until they run again, and a machine paused and resumed with neither clock moved forward keeps
  a key longer by the length of the pause.
- The window holds only while rotations succeed. A node that cannot make its next key, or cannot
  lock its page, keeps the published key, tries again every second and counts the attempts
  (onion_rotate_failed); until one succeeds that key has no bound.
- Onion key rotation does not cover: the hop keys of circuits that are alive when memory is
  taken, which open the cells of those circuits, recorded ones included, for as long as the
  circuit lives (24 h at most by default); the link key, which lives as long as the process and
  lets whoever holds it answer links in place of the node, though it opens no layer and no
  recorded link; the copies of a released onion key that the libraries left on the heap, the
  X25519 scalar on c25519 and math/big numbers on GOST; heap copies of the secret a setup was
  opened with and of hop keys, those of circuits already torn down included, which stay until
  that memory is reused and open the recorded cells of their circuit without any onion key
  (CRYPTO, known gaps).
- With -onion-rotate 0, the measurement baseline and the way the lab harness runs its nodes, the
  link key is the onion key as well and lives until the node restarts: a neighbour that kept the
  setup cells can, once the key is stolen, open that node's layers for the time it ran.
- Rotation is the node's own doing and a client cannot check it: the epoch in a descriptor shows
  that the published key changed, not that the replaced one was released. The property holds for
  a node that ran the published code and was compromised later.
- During the grace period every setup costs the node two key agreements instead of one, two VKO
  on the GOST suite (EXPERIMENT, block 6). On the testbed that is 22 minutes of every hour.
- Without node authentication a descriptor carries no lifetime, so nothing bounds how long a
  client or a mirror holds one. A setup built from an unsigned descriptor that is older than the
  grace period is refused, and the client has to fetch the descriptors again.
- Control cell tags live as long as the onion key that opened them. Once their number under a
  key reaches the bound the node refuses new setups under that key: forgetting a tag would mean
  accepting a copy again. With rotation the refusal ends when the next key is published, one
  rotation period later at most; without rotation it lasts until the node restarts. Anyone who
  builds circuits can fill the cache, each tag costing a TCP connection and a link handshake.
  This is a denial of service. At the default setup rate of 0.2 per second one address needs
  about 91 hours to fill the default 65536 tags, n addresses 91/n hours; within one rotation
  period of the testbed that takes about 90 addresses. The estimate holds for every node, since
  each keeps the per-address limits. On the testbed a cell port takes connections from client
  and relay pods only, where the cluster's network plugin enforces network policies (in CI the
  e2e fails without it).
- A tag takes 16 bytes (about 36 bytes of heap) of ordinary node memory per opened control cell
  until its onion key is released, or until restart without rotation. It holds no key, but a
  memory dump gives an upper bound on the number of circuits set up under the keys the node
  holds, and together with the onion key and a kept control cell it confirms that the node
  carried that circuit.
- The node counters are exact sums, printed to stdout once a minute by default and served on the
  loopback admin port. They carry no circuit identifiers, but with few circuits a sum describes
  single ones: on the testbed, with one client, the nodes whose cell counters grow are the nodes
  of its chain, the entry shown by mirror_requests and the exit by delivered. Whoever reads the
  node output learns that. Protection of the counters is planned
  ([#64](https://github.com/jimichi-org/jimichi/issues/64)).
- Trust in certificate issuance rests on the operator's kubeconfig and the path from the kube API
  through the kubelet into the pod: both the port-forward that carries the request and the
  certificate and the container log that gives the hash of the node signing key take that path.
  kind does not verify the kubelet certificate, so whoever controls the host or its docker network
  can substitute both during issuance and impersonate a node. That is the runtime administrator
  of the threat model.
- The integrity of the anchor equals write access to ConfigMap jimichi-ca and to the client pod
  spec: whoever can change them decides which nodes the client trusts.
- A certificate is installed once per node process, and re-enrollment, including after the
  certificate expires, needs a restart. Whoever holds the pods/portforward right on a node's pod
  can enroll a fresh node process under a CA of their own before the operator does: clients
  holding the operator's anchor refuse that node, and it stays out of service until it restarts.
  The same right lets them send a node its roster before enroll does, within the window after
  the certificate. The node list of a roster is not authenticated: such a roster must name the
  anchor that certified the node and gives it as peers only nodes whose descriptors verify under
  that anchor, so it can leave nodes out but not add one, and enroll then fails on that node.
  That is operator-level power, the runtime administrator of the threat model.
- There is no revocation beyond not_after and a node restart with a new issuance under a new CA.
  A signing key extracted from the memory of a live node impersonates that node until whichever
  of the two comes first.
- Every node restart needs scripts/enroll.sh, and enrollment needs fresh processes of all nodes:
  a process takes one certificate and one roster. The new process gets a new signing key, no
  certificate and no roster. Until then clients refuse the node and it extends no circuit, and
  readiness does not show it; it shows as a 503 on /descriptor, as cert=none and roster=0 in the
  counters line and in the client log.
- Whoever holds the CA key, that is the operator or someone who stole it during issuance, can
  certify an identity of their own for any name and address and, with a position in the network,
  substitute nodes. How often a uniformly drawn chain meets such nodes is computed and sampled
  (EXPERIMENT, block 3); what they then learn from the traffic is yet to be measured in the lab
  ([#117](https://github.com/jimichi-org/jimichi/issues/117)). Past circuits stay closed to such
  a substitution.
- Nodes publish their descriptors themselves and there is no directory: a node can show
  different keys to different roster nodes, and so to the clients of different entries.
- The clocks of nodes and clients must agree within 2 minutes (the Skew allowance). kind nodes run
  on the host clock.
- On the GOST suite every signature leaves heap copies of the signing scalar and the one-time
  number k as math/big: the request, the certificate, every timer re-signing of the descriptor,
  each half of -descriptor-ttl, and the signing at every rotation of the onion key (CRYPTO, known
  gaps). When issuance runs on a Windows host, the CA key stays in unlocked memory of a process
  without dump prevention while it issues.
- The node limits (ARCHITECTURE) give one address at most 32 of the 512 links, 4 of the 32
  concurrent handshakes, 10 new links per second after a burst of 50 and 0.2 setups per second
  after a burst of 10; an IPv6 /64 counts as one address. The shared caps equal 16 per-address
  shares of links and 8 of handshakes; once a shared cap is used up the node refuses new
  connections. This is a denial of service; each slot is held at most until its deadline (2 s
  for a handshake), the idle timeout or the circuit lifetime runs out.
- A node cannot tell a relay from a client, since the responder of a link does not authenticate
  the initiator, and any node can be an entry, so every node keeps the per-address limits. At a
  middle or exit node every circuit that came through one relay arrives from that relay's one
  address, and those circuits share one address's allowance: 32 links and 0.2 setups per second
  with bursts of 10. One client can use it up for every other client whose chain crosses the
  same two nodes in the same order. The testbed runs one client, so the allowance does not bind
  there.
- A circuit is torn down after the idle timeout and after its lifetime. The client does not
  rebuild it: the client process exits and builds a new circuit at its next start, on the testbed
  when the orchestrator restarts the pod. The moment depends only on the node parameters and the
  last cell: with constant-rate sending a circuit is never idle, and the lifetime shows only the
  age of a circuit, which the connection open time already shows.
- The cell format uses constant size and replay protection but is not full Sphinx: beyond the
  constant size there is no processing that hides the position of a node in the chain.
- A message has to fit into one cell: at most 444 bytes over three hops on either suite and 428
  over four on c25519. A longer one is refused with an error and not sent, there is no
  fragmentation and there are no size classes. The wire length says nothing about a message only
  because a message never spans cells; fragmentation with size classes is planned
  ([#68](https://github.com/jimichi-org/jimichi/issues/68)).
- Each circuit opens its own TCP connections between nodes and closes them in a cascade when it
  breaks. Connection open and close times match along the chain and are visible to a global
  observer. The correlation attack in this work uses cells only, this signal is not measured;
  adding it to the lab attack is planned ([#43](https://github.com/jimichi-org/jimichi/issues/43)).
- The correlation attack runs in laboratory conditions where the true flow labels are known.
  Transferring the estimates to a real network requires care.
- The attack that is implemented is the baseline one: a passive observer counts frames per window
  on the client-entry link and on the last link between nodes and ranks pairs of flows by Pearson
  correlation, with no time shift and on the forward direction only. Replies cross the same links
  and are not scored. An AUC near 0.5 says that this attack fails, not that a stronger one would:
  a learned correlator ([#67](https://github.com/jimichi-org/jimichi/issues/67)) and an active
  adversary with a timing watermark ([#116](https://github.com/jimichi-org/jimichi/issues/116))
  are planned.
- The correlation series run with as many nodes as hops, in a fixed order, all in one process over
  the loopback interface: without certificates or onion key rotation, with anonymous links
  between nodes and with the per-address limits off. The choice of the chain is measured
  separately and without traffic (EXPERIMENT, block 3).
- The dataset is synthetic: message traffic is generated, messages of one size with exponential
  gaps between them, not captured from real users.
- The client container with two volumes is planned, not implemented
  ([#20](https://github.com/jimichi-org/jimichi/issues/20)); this limit and the two after it
  belong to its design. Its plausible deniability will break through the environment rather than
  the cryptography: filesystem journals, shadow copies, timestamps, and wear-leveling and TRIM on
  SSDs leave traces of writes where the decoy says nothing happened. Hidden volumes of TrueCrypt
  and VeraCrypt were detected exactly this way.
- Its deniability will not protect against coercion to surrender a password: it provides a cover
  story, not immunity.
- An adversary holding several snapshots of the container over time will see changes in the areas
  the decoy claims are unused. The property is not claimed against that adversary.
- Latency measurement needs a clock finer than a millisecond. On a Windows host short intervals
  read as zero, so latency runs happen in Linux (a container or the cluster), not on the
  development host.
- The model does not cover a global observer, compromise of the user's device, or side-channel
  attacks.
