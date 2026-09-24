# Limits of applicability

English | [Русский](../ru/LIMITATIONS.md)

- The testbed is a laboratory one: nodes are containers on a single machine. Network delays and
  the separation between operators are modelled, not reproduced.
- The GOST implementation is not a certified cryptographic facility. It applies to systems handling
  commercial data, not to state information systems or significant critical infrastructure. The
  algorithms are the same and conformance is checked against the test vectors from the standards,
  but no protection class is claimed.
- Go runtime: cipher libraries expand the key into a round key schedule on the heap and the garbage
  collector may copy it. secmem protects only its own buffers.
- mlock prevents swapping, not reading by a process with sufficient privileges. Against root on the
  machine hosting a node, process-level measures do not work; that is the expected result.
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
