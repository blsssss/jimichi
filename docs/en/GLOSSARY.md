# Glossary

English | [Русский](../ru/GLOSSARY.md)

| Term | Meaning |
|---|---|
| Cell | the unit of transmission, constant 512 bytes |
| Layer | one level of encryption, stripped by one node of the chain |
| Hop | a step between neighbouring nodes of the chain |
| Circuit | the nodes a message travels through, three by default, drawn by the client from its node list; also called the chain |
| Node list | the static list of nodes a client draws its chains from; before a chain is built every listed node whose bundle the entry serves is verified; for a random chain the entry may leave out at most -missing nodes (one by default, never more than the list holds beyond -hops), and those are not used |
| Entry, middle, exit | the places of a node in a chain: the entry is the first node and the only one the client connects to, the middle is between the entry and the exit, the exit is the last node: it opens the innermost layer and on the testbed echoes the message back along the circuit; delivery to a recipient client is planned ([#18](https://github.com/jimichi-org/jimichi/issues/18)) |
| Rogue node | a node the adversary holds: a compromised one or one inserted with a valid certificate |
| Fixed chain | the first nodes of the list in the listed order instead of a random choice, for measurements that need a known path |
| Ephemeral key | a key that lives for one session; its buffer is zeroed afterwards, while the copies the libraries made stay on the heap until that memory is reused (CRYPTO, "Known gaps") |
| UKM | the VKO factor binding an agreed secret to a session; in the GOST suite it is the first 8 bytes of the transcript hash |
| Transcript | the public data of one key exchange in an unambiguous layout: the version, the parameters of the exchange and the public keys of both sides (CRYPTO, "Key derivation") |
| Key context | the transcript hash together with the suite (Context); it enters every agreement and every key derivation, and the provider derives no key without it |
| AEAD | authenticated encryption with associated data |
| Cover traffic | cells with no payload, sent to mask when a real message leaves: on top of the messages or in the empty slots of a constant-rate schedule; how much they mask is measured, not assumed (EXPERIMENT, block 1) |
| Link padding | a frame a node sends to its neighbour on an empty tick of its schedule; the neighbour drops it |
| Own-clock sending | a node sends one cell per tick of its own timer, not at the moment the cell arrives |
| Padding | bytes added to reach the constant cell size |
| Correlation attack | linking sender and recipient by timings and volumes |
| Unlinkability | the property that an observer cannot link sender and recipient |
| Forward secrecy | compromise of a long-term key does not expose past sessions |
| Trust anchor | the CA public key the client trusts in advance, as the string `<suite>:<base64>` |
| Node certificate | a CA-signed record binding a node's name, address and signing key for a validity period |
| Node signing key | the node's long-term signing pair (identity key): it signs the certificate request and the descriptor and takes no part in key agreement |
| Onion key | the node key the client agrees a layer secret with during circuit setup; with rotation a node replaces it by epochs |
| Link key | the node public key (LinkPub in the descriptor) the initiator of a link to that node mixes into the handshake: the client for its entry, a node for the next node of a circuit |
| Node descriptor | a record signed by the node signing key: certificate hash, link key, onion key, epoch and a short validity |
| Onion key epoch | the number of the node's onion key in its descriptor: 0 for the first key of a process, one more after every rotation; the link key does not change with it |
| Grace period | the time a node still holds a replaced onion key: the descriptor lifetime plus the clock allowance after the rotation |
| Node bundle | the node certificate and descriptor in one JSON object, which the node serves to clients |
| Operator roster | the list of node names and addresses the operator allows certificates for |
| Node roster | the anchor with the names and addresses of the nodes of one issuance, sent to each of them; a node extends circuits only to roster nodes |
| Descriptor mirror | the node's own bundle and the bundles of the roster nodes it currently holds, served on /descriptors so that a client asks its entry alone; a roster node whose bundle is missing or expired is left out |
| Certificate issuance | the CA checks a node's signed request, carrying a nonce the CA chose, against the operator roster and signs the certificate |
| Counter order | on every link a node accepts only the counter one above the previous one, anything else closes the circuit; the client takes the numbers of replies the same way; the replay defence |
| Memory dump | a snapshot of process memory; the key extraction scenarios that will search it are planned ([#24](https://github.com/jimichi-org/jimichi/issues/24)) |
| ROC, AUC | the error curve and the area under it, the measure of attack success |
| Bootstrap | a resampling method for confidence intervals |
