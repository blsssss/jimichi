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
  often, the node's queue fills up and the excess cells are lost, and with equal periods a missed
  tick can never be caught up. The testbed gives nodes a period 5% shorter than the client's.
- A link is covered by own-clock sending only if the node sending on it has the measure turned on.
  The client cannot check that the nodes of its chain do: a node without the measure carries the
  timing onwards, and the protection is gone on its outgoing links.
- Every circuit runs over a connection of its own, and a second setup on a link that already
  carries a circuit is dropped. Otherwise a second timer on the same link would double its frame
  rate and give away the number of circuits.
- The circuit setup cell leaves at once, not on the node's clock. Together with the TCP connection
  opening it marks the start of the circuit on every link, which is the same signal as the moment
  the connection opens.
- The circuit layers have no forward secrecy against a neighbour: the node key lives until the node
  restarts and takes part in the layer agreement. A neighbour that kept the setup cells can, once
  the key is stolen, open that node's layers for the time it ran. A wire capture cannot be read
  without the links' ephemeral keys.
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
