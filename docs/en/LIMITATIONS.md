# Limits of applicability

English | [Русский](../ru/LIMITATIONS.md)

- The testbed is a laboratory one: nodes are containers on a single machine. Network delays and
  the separation between operators are modelled, not reproduced.
- The GOST implementation is not a certified cryptographic facility. It applies to systems handling
  commercial data, not to state information systems or significant critical infrastructure. The
  algorithms are the same and conformance is checked against the test vectors from the standards,
  but no protection class is claimed.
- Go runtime: libraries keep their own copies of keys on the heap, and the AEAD working key in
  x/crypto stays there for the life of the circuit. secmem protects only its own buffers; CRYPTO
  lists the copies.
- mlock prevents swapping, not reading by a process with sufficient privileges. Against root on the
  machine hosting a node, process-level measures do not work; that is the expected result.
- Sending on a node's own clock requires the node's period to be shorter than the client's, with a
  margin of a few percent. The node does not know how fast a client sends: if the client sends more
  often, the node's queue fills up and the circuit closes, since the node cannot lose a cell of a
  circuit. With equal or longer periods a missed tick can never be caught up, and the queue fills
  up sooner or later. The testbed gives nodes a period 5% shorter than the client's.
- Any break in the counter order closes the circuit. A neighbouring node can cause one with a
  single cell. A party on the wire cannot put a frame of its own on an authenticated link, but a
  frame it damages or a connection it breaks closes the circuit all the same. This is a denial of
  service.
- A link is authenticated in one direction, to the node it leads to. The responder does not
  authenticate the initiator: a node cannot tell a roster node from a client or from anyone else
  who connects to its cell port.
- The baseline without node authentication (-auth=false) extends a circuit to any address named
  in the setup cell, and its links between nodes are anonymous: they hide headers from a passive
  observer only. It serves measurements on the testbed.
- The entry serves the bundles of the whole chain. It cannot alter them, but it can withhold
  them, which is a denial of service, and it sees when a client prepares a circuit: the request
  for the descriptors precedes the setup.
- A node keeps a peer's descriptor until it expires. After a peer restarts, the mirror serves its
  previous bundle for up to the descriptor lifetime (1 h), and circuits through that peer close
  at setup, since the new process holds another link key.
- A link is covered by own-clock sending only if the node sending on it has the measure turned on.
  The client cannot check that the nodes of its chain do: a node without the measure carries the
  timing onwards, and the protection is gone on its outgoing links.
- Every circuit runs over a connection of its own, and a second setup on a link that already
  carries a circuit is dropped. Otherwise a second timer on the same link would double its frame
  rate and give away the number of circuits.
- Without own-clock sending the exit's reply leaves after the message is delivered, and at once for
  a cover cell. The delivery time enters the moment of the reply; on the testbed delivery is an
  echo taking microseconds, a real recipient would make it noticeable.
- The circuit setup cell leaves at once, not on the node's clock. Together with the TCP connection
  opening it marks the start of the circuit on every link, which is the same signal as the moment
  the connection opens.
- The circuit layers have no forward secrecy against a neighbour: the node key lives until the node
  restarts and takes part in the layer agreement. A neighbour that kept the setup cells can, once
  the key is stolen, open that node's layers for the time it ran. A wire capture cannot be read
  without the links' ephemeral keys.
- Control cell tags live as long as the node key, and the key lives until the node restarts. Once
  their number reaches the bound the node refuses new circuits until it restarts: forgetting a tag
  would mean accepting a copy again. Anyone who builds circuits can fill the cache, each tag
  costing a TCP connection and a link handshake. This is a denial of service. At the default
  setup rate of 0.2 per second one address needs about 91 hours to fill the default 65536 tags,
  n addresses 91/n hours. This estimate is for the entry. On the testbed a forwarding node takes
  cells only from the previous relay where the cluster's network plugin enforces network policies
  (in CI the e2e fails without it), so every setup that reaches it has first spent a token at the
  entry; a node without per-address limits that anyone can reach would be bounded only by how
  fast it completes handshakes.
- A tag takes 16 bytes (about 36 bytes of heap) of ordinary node memory per opened control cell
  until restart. It holds no key, but a memory dump gives an upper bound on the number of
  circuits, and together with the node key and a kept control cell it confirms that the node
  carried that circuit.
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
  the certificate. Such a roster must name the anchor that certified the node and gives it as
  peers only nodes whose descriptors verify under that anchor, so it can leave nodes out but not
  add one, and enroll then fails on that node. That is operator-level power, the runtime
  administrator of the threat model.
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
  substitute nodes. What that costs the properties of the system is yet to be
  measured in the lab (experiment block 3). Past circuits stay closed to such a substitution.
- Nodes publish their descriptors themselves and there is no directory: a node can show
  different keys to different roster nodes, and so to the clients of different entries.
- The clocks of nodes and clients must agree within 2 minutes (the Skew allowance). kind nodes run
  on the host clock.
- On the GOST suite every signature leaves heap copies of the signing scalar and the one-time
  number k as math/big: the request, the certificate and every timer re-signing of the descriptor,
  each half of its lifetime (CRYPTO, known gaps). When issuance runs on a Windows host, the CA key
  stays in unlocked memory of a process without dump prevention while it issues.
- The node limits (ARCHITECTURE) give one address at most 32 of the 512 links, 4 of the 32
  concurrent handshakes, 10 new links and 0.2 setups per second; an IPv6 /64 counts as one
  address. The shared caps equal 16 per-address shares of links and 8 of handshakes; once a
  shared cap is used up the node refuses new connections. This is a denial of service; each slot
  is held at most until its deadline (2 s for a handshake), the idle timeout or the circuit
  lifetime runs out.
- A node cannot tell a relay from a client, since the responder of a link does not authenticate
  the initiator, and on a middle or exit node every circuit arrives from the previous relay's one
  address. Per-address limits there would let one client use up the allowance of every circuit
  through that pair of relays, so a node used as middle or exit runs without them and relies on
  the global caps only;
  a client that entered the chain at such a node would meet only the global caps as well. The
  testbed keeps the per-address limits on the entry relay-1, turns them off on relay-2 and
  relay-3, and lets only the previous relay reach their cell ports (network policy). This is a
  property of the fixed testbed chain: with a random chain (planned) any relay can be an entry,
  and a policy by position no longer applies.
- A circuit is torn down after the idle timeout and after its lifetime, and the client then builds
  a new one. The moment depends only on the node parameters and the last cell: with constant-rate
  sending a circuit is never idle, and the lifetime shows only the age of a circuit, which the
  connection open time already shows.
- The cell format uses constant size and replay protection but is not full Sphinx: beyond the
  constant size there is no processing that hides the position of a node in the chain.
- Each circuit opens its own TCP connections between nodes and closes them in a cascade when it
  breaks. Connection open and close times match along the chain and are visible to a global
  observer. The correlation attack in this work uses cells only, this signal is not measured.
- The correlation attack runs in laboratory conditions where the true flow labels are known.
  Transferring the estimates to a real network requires care.
- The dataset is synthetic: cover traffic is generated, not captured from real users.
- Plausible deniability of the container breaks through the environment rather than the
  cryptography: filesystem journals, shadow copies, timestamps, and wear-leveling and TRIM on SSDs
  leave traces of writes where the decoy says nothing happened. Hidden volumes of TrueCrypt and
  VeraCrypt were detected exactly this way.
- Deniability does not protect against coercion to surrender a password: it provides a cover story,
  not immunity.
- An adversary holding several snapshots of the container over time sees changes in the areas the
  decoy claims are unused. The property is not claimed against that adversary.
- Latency measurement needs a clock finer than a millisecond. On a Windows host short intervals
  read as zero, so latency runs happen in Linux (a container or the cluster), not on the
  development host.
- The model does not cover a global observer, compromise of the user's device, or side-channel
  attacks.
